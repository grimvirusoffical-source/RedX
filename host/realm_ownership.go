package host

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sync"

	"redx/billing"
	"redx/internal/accountscope"
)

type realmOwnerBinding struct {
	Issuer       string `json:"issuer"`
	Subject      string `json:"subject"`
	CanonicalID  string `json:"canonicalId"`
	OwnershipKey string `json:"ownershipKey"`
}
type realmOwnerFile struct {
	Version  int                          `json:"version"`
	Bindings map[string]realmOwnerBinding `json:"bindings"`
}
type realmOwnerStore struct {
	mu       sync.Mutex
	path     string
	bindings map[string]realmOwnerBinding
}

func (b realmOwnerBinding) valid() bool {
	key, ok := accountscope.Key(b.Issuer, b.Subject)
	return ok && b.OwnershipKey == key && b.CanonicalID == accountscope.PublicID(b.Subject)
}
func openRealmOwners(path string) (*realmOwnerStore, error) {
	s := &realmOwnerStore{path: path, bindings: map[string]realmOwnerBinding{}}
	if path == "" {
		return s, nil
	}
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || info.Mode()&os.ModeSymlink != 0 || info.Size() > 16<<20 || (runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0) {
		return nil, errors.New("invalid realm ownership metadata file")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(data) > 16<<20 {
		return nil, errors.New("realm ownership metadata too large")
	}
	f, err := parseRealmOwners(data)
	if err != nil {
		return nil, err
	}
	s.bindings = f.Bindings
	return s, nil
}

func parseRealmOwners(data []byte) (realmOwnerFile, error) {
	var f realmOwnerFile
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if len(data) > 16<<20 || decoder.Decode(&f) != nil || f.Version != 1 || f.Bindings == nil {
		return f, errors.New("invalid realm ownership metadata")
	}
	if decoder.Decode(new(interface{})) != io.EOF {
		return f, errors.New("invalid trailing realm ownership metadata")
	}
	for key, b := range f.Bindings {
		if key != b.OwnershipKey || !b.valid() {
			return f, errors.New("invalid realm ownership binding")
		}
	}
	return f, nil
}

// A restored fresh key, tenant, plan or usage record requires the same complete
// registry tuple. Missing fields mean legacy, never inferred fresh ownership.
func validateSnapshotOwnership(sc *SnapshotContents) error {
	bindings := map[string]realmOwnerBinding{}
	if sc.RealmOwners != nil {
		f, err := parseRealmOwners(sc.RealmOwners)
		if err != nil {
			return err
		}
		bindings = f.Bindings
	}
	valid := func(key, issuer, subject string) bool {
		if !accountscope.MetadataMatches(key, issuer, subject) {
			return false
		}
		if issuer != accountscope.FreshIssuer {
			return true
		}
		b, exists := bindings[key]
		return exists && b.Issuer == issuer && b.Subject == subject && b.valid()
	}
	for _, k := range sc.Keys {
		if !valid(k.Owner, k.OwnerIssuer, k.OwnerSubject) {
			return errors.New("snapshot: invalid key ownership binding")
		}
	}
	if sc.Tenants != nil {
		var f tenantFile
		if json.Unmarshal(sc.Tenants, &f) != nil {
			return errors.New("snapshot: invalid tenant metadata")
		}
		for _, r := range f.DBs {
			if !valid(r.Account, r.OwnerIssuer, r.OwnerSubject) {
				return errors.New("snapshot: invalid tenant ownership binding")
			}
		}
	}
	if sc.BillingPlans != nil {
		var f struct {
			Plans map[string]billing.Plan `json:"plans"`
		}
		if json.Unmarshal(sc.BillingPlans, &f) != nil || f.Plans == nil {
			return errors.New("snapshot: invalid billing plans")
		}
		for key, p := range f.Plans {
			if p.Account != key || !valid(key, p.OwnerIssuer, p.OwnerSubject) {
				return errors.New("snapshot: invalid plan ownership binding")
			}
		}
	}
	if sc.BillingUsage != nil {
		var f struct {
			Usage map[string]billing.Usage `json:"usage"`
		}
		if json.Unmarshal(sc.BillingUsage, &f) != nil || f.Usage == nil {
			return errors.New("snapshot: invalid billing usage")
		}
		for key, u := range f.Usage {
			if u.Account != key || !valid(key, u.OwnerIssuer, u.OwnerSubject) {
				return errors.New("snapshot: invalid usage ownership binding")
			}
		}
	}
	return nil
}
func (s *realmOwnerStore) bind(b realmOwnerBinding, occupied func(string) bool) error {
	if s == nil || !b.valid() {
		return errors.New("invalid realm ownership binding")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if old, exists := s.bindings[b.OwnershipKey]; exists {
		if old != b {
			return errors.New("immutable realm binding conflict")
		}
		return nil
	}
	if occupied(b.OwnershipKey) {
		return errors.New("unclaimed ownership metadata cannot be adopted")
	}
	next := make(map[string]realmOwnerBinding, len(s.bindings)+1)
	for key, v := range s.bindings {
		next[key] = v
	}
	next[b.OwnershipKey] = b
	if s.path != "" {
		data, err := json.MarshalIndent(realmOwnerFile{1, next}, "", " ")
		if err != nil {
			return err
		}
		file, err := os.CreateTemp(filepath.Dir(s.path), ".realm-owner-*")
		if err != nil {
			return err
		}
		tmp := file.Name()
		defer os.Remove(tmp)
		if err = file.Chmod(0o600); err == nil {
			_, err = file.Write(data)
		}
		if err == nil {
			err = file.Sync()
		}
		closeErr := file.Close()
		if err == nil {
			err = closeErr
		}
		if err != nil {
			return err
		}
		if err = os.Rename(tmp, s.path); err != nil {
			return err
		}
		if runtime.GOOS != "windows" {
			dir, err := os.Open(filepath.Dir(s.path))
			if err != nil {
				return err
			}
			err = dir.Sync()
			dir.Close()
			if err != nil {
				return err
			}
		}
	}
	s.bindings = next
	return nil
}
func (s *realmOwnerStore) bytes() []byte {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.bytesLocked()
}

func (s *realmOwnerStore) bytesLocked() []byte {
	if len(s.bindings) == 0 {
		return nil
	}
	b, _ := json.MarshalIndent(realmOwnerFile{1, s.bindings}, "", " ")
	return b
}

// Freeze new registry bindings until all backup metadata and key hashes have
// been collected. A key created concurrently must not outlive its binding in
// the archive. This does not promise a transaction with provider webhooks.
func (s *realmOwnerStore) freezeSnapshot() ([]byte, func()) {
	if s == nil {
		return nil, func() {}
	}
	s.mu.Lock()
	return s.bytesLocked(), s.mu.Unlock
}

func (s *realmOwnerStore) matches(key, issuer, subject string) bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	b, ok := s.bindings[key]
	return ok && b.valid() && b.Issuer == issuer && b.Subject == subject
}
func (h *Host) keyOwnershipAllowed(k KeyRecord) bool {
	if !accountscope.MetadataMatches(k.Owner, k.OwnerIssuer, k.OwnerSubject) {
		return false
	}
	if k.OwnerIssuer == accountscope.FreshIssuer {
		return h.realmOwners.matches(k.Owner, k.OwnerIssuer, k.OwnerSubject)
	}
	return true
}
func (h *Host) bindRealmIdentity(id *AccountIdentity) bool {
	if id == nil {
		return false
	}
	if id.OwnershipIssuer == "" {
		return id.ownershipKey() != ""
	}
	b := realmOwnerBinding{id.OwnershipIssuer, id.OwnershipSubject, id.Sub, id.OwnershipKey}
	return h.realmOwners.bind(b, func(key string) bool {
		if h.tenants.hasAccount(key) {
			return true
		}
		for _, rec := range h.KS.List() {
			if rec.Owner == key {
				return true
			}
		}
		if h.billing.OwnerMetadataExists(key) {
			return true
		}
		return h.billing.Usage().KnownAccount(key)
	}) == nil
}
func (a *AccountIdentity) ownershipKey() string {
	if a == nil {
		return ""
	}
	if a.OwnershipIssuer != "" {
		if accountscope.MetadataMatches(a.OwnershipKey, a.OwnershipIssuer, a.OwnershipSubject) {
			return a.OwnershipKey
		}
		return ""
	}
	if accountscope.ValidLegacySubject(a.Sub) {
		return a.Sub
	}
	return ""
}
