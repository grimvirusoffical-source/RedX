package host

import (
	"testing"
	"time"
)

func TestPairStoreExpiryAndSingleUse(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p := &pairStore{now: func() time.Time { return now }}
	spec := CreateSpec{DB: "default", Scope: ScopeRead}
	code, _, ok := p.issue(spec, "k1")
	if !ok {
		t.Fatal("issue")
	}
	// still valid just before 5 minutes
	now = now.Add(pairTTL - time.Second)
	if _, r := p.redeem(code, "c"); r != pairOK {
		t.Fatalf("code should still work: %v", r)
	}
	if _, r := p.redeem(code, "c"); r != pairBad {
		t.Fatal("second use must fail")
	}
	// expired after 5 minutes
	code2, _, _ := p.issue(spec, "k1")
	now = now.Add(pairTTL)
	if _, r := p.redeem(code2, "c2"); r != pairBad {
		t.Fatal("expired code must fail")
	}
	if p.pendingCount() != 0 {
		t.Fatal("expired codes must be dropped")
	}
	// the cap on unused codes
	for i := 0; i < pairMaxPending; i++ {
		if _, _, ok := p.issue(spec, "k"); !ok {
			t.Fatalf("issue %d refused early", i)
		}
	}
	if _, _, ok := p.issue(spec, "k"); ok {
		t.Fatal("pending cap not enforced")
	}
}

func TestPairStoreThrottleWindowReopens(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p := &pairStore{now: func() time.Time { return now }}
	for i := 0; i < pairFailPerIP; i++ {
		if _, r := p.redeem("RP-AAAAA-AAAAA", "x"); r != pairBad {
			t.Fatalf("attempt %d: %v", i, r)
		}
	}
	if _, r := p.redeem("RP-AAAAA-AAAAA", "x"); r != pairThrottled {
		t.Fatal("not throttled")
	}
	if _, r := p.redeem("RP-AAAAA-AAAAA", "other"); r != pairBad {
		t.Fatal("another client must not be throttled by x")
	}
	now = now.Add(pairFailWindow + time.Second)
	if _, r := p.redeem("RP-AAAAA-AAAAA", "x"); r != pairBad {
		t.Fatal("throttle should clear after the window")
	}
}

func TestNormPairCode(t *testing.T) {
	for in, want := range map[string]string{"RP-ABCDE-FGHJK": "RP-ABCDE-FGHJK", "rp abcde fghjk": "RP-ABCDE-FGHJK", "abcdefghjk": "RP-ABCDE-FGHJK", "RP-ABC": "", "": ""} {
		if got := normPairCode(in); got != want {
			t.Errorf("%q -> %q want %q", in, got, want)
		}
	}
}
