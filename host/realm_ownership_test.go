package host

import (
	"bytes"
	"encoding/json"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"

	"redx/billing"
	"redx/internal/accountscope"
)

func realmBindingFixture(subject string) realmOwnerBinding {
	key, _ := accountscope.Key(accountscope.FreshIssuer, subject)
	return realmOwnerBinding{accountscope.FreshIssuer, subject, accountscope.PublicID(subject), key}
}

func TestRealmOwnersPersistAndRefuseUnclaimedNamespace(t *testing.T) {
	path := filepath.Join(t.TempDir(), "realm-owners.json")
	s, err := openRealmOwners(path)
	if err != nil {
		t.Fatal(err)
	}
	b := realmBindingFixture("shared")
	if err := s.bind(b, func(string) bool { return true }); err == nil {
		t.Fatal("unclaimed metadata adopted")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("failed bind changed disk")
	}
	if err := s.bind(b, func(string) bool { return false }); err != nil {
		t.Fatal(err)
	}
	before, _ := os.ReadFile(path)
	s, err = openRealmOwners(path)
	if err != nil || !s.matches(b.OwnershipKey, b.Issuer, b.Subject) {
		t.Fatal("binding lost after reopen", err)
	}
	if s.matches(b.OwnershipKey, b.Issuer, "other") || s.matches(b.CanonicalID, b.Issuer, b.Subject) {
		t.Fatal("public/other tuple matched")
	}
	if err := s.bind(b, func(string) bool { t.Fatal("existing binding queried adoption callback"); return true }); err != nil {
		t.Fatal(err)
	}
	bad := b
	bad.CanonicalID = "other"
	if err := s.bind(bad, func(string) bool { return false }); err == nil {
		t.Fatal("binding rewritten")
	}
	after, _ := os.ReadFile(path)
	if !bytes.Equal(before, after) {
		t.Fatal("idempotent/invalid binding changed metadata")
	}
	var data map[string]interface{}
	_ = json.Unmarshal(before, &data)
	data["ownerIssuerTypo"] = "ignored?"
	corrupt, _ := json.Marshal(data)
	if err := os.WriteFile(path, corrupt, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := openRealmOwners(path); err == nil {
		t.Fatal("unknown registry metadata ignored")
	}
}

func TestRealmOwnershipMetadataFailsClosedAtLegacyAndKeyBoundaries(t *testing.T) {
	b := realmBindingFixture("shared")
	h := &Host{accts: newAccountStore(), realmOwners: &realmOwnerStore{bindings: map[string]realmOwnerBinding{b.OwnershipKey: b}}}
	for _, id := range []AccountIdentity{{Sub: b.OwnershipKey}, {Sub: "bad\nsubject"}, {Sub: b.CanonicalID, OwnershipIssuer: b.Issuer, OwnershipSubject: b.Subject, OwnershipKey: b.OwnershipKey}} {
		token, _ := h.accts.newSession(id)
		if _, ok := h.resolveAccount(token); ok {
			t.Fatal("native legacy session accepted internal/fresh identity")
		}
	}
	token, _ := h.accts.newSession(AccountIdentity{Sub: b.CanonicalID})
	if pr, ok := h.resolveAccount(token); !ok || pr.tenantSub() != b.CanonicalID {
		t.Fatal("legacy public-shaped ID denied")
	}
	key := KeyRecord{Owner: b.OwnershipKey, OwnerIssuer: b.Issuer, OwnerSubject: b.Subject}
	if key.Active(time.Now()) != nil || !h.keyOwnershipAllowed(key) {
		t.Fatal("bound metadata rejected")
	}
	for _, invalid := range []KeyRecord{{Owner: b.OwnershipKey}, {Owner: b.CanonicalID, OwnerIssuer: b.Issuer, OwnerSubject: b.Subject}, {Owner: b.OwnershipKey, OwnerIssuer: b.Issuer, OwnerSubject: "other"}} {
		if invalid.Active(time.Now()) == nil || h.keyOwnershipAllowed(invalid) {
			t.Fatal("forged/missing ownership accepted")
		}
	}
	h.realmOwners = &realmOwnerStore{bindings: map[string]realmOwnerBinding{}}
	if h.keyOwnershipAllowed(key) {
		t.Fatal("fresh key authenticated without persistent registry")
	}
}

func TestRealmAuthenticatorRequiresRegistryResolverEvenWithValidKeyHash(t *testing.T) {
	b := realmBindingFixture("shared")
	ks, err := OpenKeystore(filepath.Join(t.TempDir(), "keys.red-xai-keys"), KeystoreOptions{ArgonMem: 64, ArgonTime: 1})
	if err != nil {
		t.Fatal(err)
	}
	fresh, _, err := ks.Create(CreateSpec{DB: "app", Scope: ScopeRead, Owner: b.OwnershipKey, OwnerIssuer: b.Issuer, OwnerSubject: b.Subject})
	if err != nil {
		t.Fatal(err)
	}
	legacy, _, err := ks.Create(CreateSpec{DB: "app", Scope: ScopeRead, Owner: b.CanonicalID})
	if err != nil {
		t.Fatal(err)
	}
	au, _ := NewAuditor("")
	a := NewAuthenticator(ks, au, 0, 0, false)
	request := func(key string) bool {
		r := httptest.NewRequest("GET", "http://localhost/v1/db/app/files", nil)
		r.Header.Set("Authorization", "Bearer "+key)
		_, _, err := a.Authenticate(r)
		return err == nil
	}
	if request(fresh) || !request(legacy) {
		t.Fatal("missing registry resolver did not preserve legacy-only auth")
	}
	h := &Host{realmOwners: &realmOwnerStore{bindings: map[string]realmOwnerBinding{b.OwnershipKey: b}}}
	a.ownerMetadata = h.keyOwnershipAllowed
	if !request(fresh) {
		t.Fatal("valid persistent registry resolver denied key")
	}
}

func TestRealmLegacyOnlyBackupKeepsOriginalArchiveLayout(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "dbs"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "billing"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "billing", "plans.json"), []byte(`{"plans":{},"events":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if err := offlineCopy(dir, &archive, ""); err != nil {
		t.Fatal(err)
	}
	sc, err := ExtractSnapshot(bytes.NewReader(archive.Bytes()), filepath.Join(t.TempDir(), "dbs"))
	if err != nil {
		t.Fatal(err)
	}
	if sc.RealmOwners != nil || sc.BillingPlans != nil || sc.BillingUsage != nil {
		t.Fatal("legacy-only archive unexpectedly gained realm members")
	}
}

func TestRealmSnapshotRequiresEveryFreshTupleAndRefusesMixedRestore(t *testing.T) {
	b := realmBindingFixture("shared")
	marshal := func(v interface{}) []byte {
		data, err := json.Marshal(v)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	sc := &SnapshotContents{
		Keys:         []KeyRecord{{Owner: b.OwnershipKey, OwnerIssuer: b.Issuer, OwnerSubject: b.Subject}},
		RealmOwners:  marshal(realmOwnerFile{1, map[string]realmOwnerBinding{b.OwnershipKey: b}}),
		Tenants:      marshal(tenantFile{DBs: map[string]tenantRec{"db": {Account: b.OwnershipKey, OwnerIssuer: b.Issuer, OwnerSubject: b.Subject}}}),
		BillingPlans: marshal(map[string]interface{}{"plans": map[string]billing.Plan{b.OwnershipKey: {Account: b.OwnershipKey, OwnerIssuer: b.Issuer, OwnerSubject: b.Subject}}}),
		BillingUsage: marshal(map[string]interface{}{"usage": map[string]billing.Usage{b.OwnershipKey: {Account: b.OwnershipKey, OwnerIssuer: b.Issuer, OwnerSubject: b.Subject}}}),
	}
	if err := validateSnapshotOwnership(sc); err != nil {
		t.Fatal(err)
	}
	for _, field := range []string{"registry", "key", "tenant", "plan", "usage"} {
		t.Run(field, func(t *testing.T) {
			bad := *sc
			switch field {
			case "registry":
				bad.RealmOwners = nil
			case "key":
				bad.Keys = []KeyRecord{{Owner: b.OwnershipKey}}
			case "tenant":
				bad.Tenants = marshal(tenantFile{DBs: map[string]tenantRec{"db": {Account: b.OwnershipKey}}})
			case "plan":
				bad.BillingPlans = marshal(map[string]interface{}{"plans": map[string]billing.Plan{b.OwnershipKey: {Account: b.OwnershipKey}}})
			case "usage":
				bad.BillingUsage = marshal(map[string]interface{}{"usage": map[string]billing.Usage{b.OwnershipKey: {Account: b.OwnershipKey}}})
			}
			if validateSnapshotOwnership(&bad) == nil {
				t.Fatal("missing ownership fields accepted")
			}
		})
	}
	root := filepath.Join(t.TempDir(), "dbs")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	var archive bytes.Buffer
	if err := writeSnapshot(&archive, root, nil, nil, &snapshotExtra{realmOwners: sc.RealmOwners}); err != nil {
		t.Fatal(err)
	}
	dest := t.TempDir()
	if err := os.WriteFile(filepath.Join(dest, "tenants.json"), []byte(`{"dbs":{}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := OfflineRestore(dest, bytes.NewReader(archive.Bytes()), "", true); err == nil {
		t.Fatal("force merged fresh registry into old ownership metadata")
	}
	if _, err := os.Stat(filepath.Join(dest, "realm-owners.json")); !os.IsNotExist(err) {
		t.Fatal("failed restore modified registry")
	}
}
