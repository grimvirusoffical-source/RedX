package billing

import (
	"path/filepath"
	"testing"
	"time"

	"redx/internal/accountscope"
)

func TestRealmPlansAndUsagePersistDistinctFromLegacyPublicDTO(t *testing.T) {
	private, _ := accountscope.Key(accountscope.FreshIssuer, "same")
	legacy := accountscope.PublicID("same")
	dir := t.TempDir()
	store, err := OpenStore(filepath.Join(dir, "plans.json"))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	if err := store.Put(Plan{Account: legacy, Tier: "basic", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	if _, ok := store.Get(private); ok {
		t.Fatal("fresh inherited legacy plan")
	}
	if err := store.Put(Plan{Account: private, Tier: "emerald", Status: "active"}); err == nil {
		t.Fatal("unlabelled internal plan accepted")
	}
	if err := store.Put(Plan{Account: private, OwnerIssuer: accountscope.FreshIssuer, OwnerSubject: "same", Tier: "emerald", Status: "active"}); err != nil {
		t.Fatal(err)
	}
	usage, err := OpenUsageStore(filepath.Join(dir, "usage.json"))
	if err != nil {
		t.Fatal(err)
	}
	q := Quota{TrafficBytes: 100}
	if err := usage.AddTraffic(legacy, q, 7, now, time.Time{}); err != nil {
		t.Fatal(err)
	}
	if err := usage.AddTraffic(private, q, 11, now, time.Time{}); err != nil {
		t.Fatal(err)
	}
	store, err = OpenStore(filepath.Join(dir, "plans.json"))
	if err != nil {
		t.Fatal(err)
	}
	for account, tier := range map[string]string{legacy: "basic", private: "emerald"} {
		p, ok := store.Get(account)
		if !ok || p.Account != account || p.Tier != tier {
			t.Fatal("plan ownership changed on reopen")
		}
	}
	usage, err = OpenUsageStore(filepath.Join(dir, "usage.json"))
	if err != nil {
		t.Fatal(err)
	}
	old := usage.Get(legacy, now, time.Time{})
	fresh := usage.Get(private, now, time.Time{})
	if old.TrafficBytes != 7 || fresh.TrafficBytes != 11 || old.OwnerIssuer != "" || fresh.OwnerIssuer != accountscope.FreshIssuer || fresh.OwnerSubject != "same" {
		t.Fatal("usage crossed namespace or lost tuple")
	}
	// A map key with someone else's Account field must not grant that row.
	store.Plans[private] = Plan{Account: legacy, Tier: "basic", Status: "active"}
	if _, ok := store.Get(private); ok {
		t.Fatal("mismatched map key/owner plan accepted")
	}
}
