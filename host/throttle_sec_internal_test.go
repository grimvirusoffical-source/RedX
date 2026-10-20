package host

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Concurrent attempts can never take more than max slots in a window.
func TestFailTrackerReserveAtomic(t *testing.T) {
	f := newFailTracker(20, time.Minute)
	var got int32
	var wg sync.WaitGroup
	for i := 0; i < 200; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok := f.reserve("1.2.3.4"); ok {
				atomic.AddInt32(&got, 1)
			}
		}()
	}
	wg.Wait()
	if got != 20 {
		t.Fatalf("reserved %d slots, want 20", got)
	}
	if _, ok := f.reserve("5.6.7.8"); !ok {
		t.Fatal("other ip blocked")
	}
}

// Successful attempts release their slot, so they never count as failures.
func TestFailTrackerReleaseOnSuccess(t *testing.T) {
	f := newFailTracker(3, time.Minute)
	for i := 0; i < 100; i++ {
		if _, ok := f.reserve("ip"); !ok {
			t.Fatalf("success %d blocked", i)
		}
		f.release("ip")
	}
	for i := 0; i < 3; i++ {
		f.reserve("ip")
	}
	if wait, ok := f.reserve("ip"); ok || wait <= 0 {
		t.Fatal("4th failure must be throttled with a wait")
	}
}

// One client exhausting its failures must not lock out other clients (F4).
func TestPairOneClientCannotLockOutOthers(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p := &pairStore{now: func() time.Time { return now }}
	for i := 0; i < 1000; i++ {
		p.redeem(fmt.Sprintf("RP-%05d-%05d", 0, i), "attacker")
	}
	code, _, ok := p.issue(CreateSpec{DB: "default", Scope: ScopeRead}, "k")
	if !ok {
		t.Fatal("issue")
	}
	if _, r := p.redeem(code, "victim"); r != pairOK {
		t.Fatalf("victim redeem: %v", r)
	}
	if _, r := p.redeem("RP-ZZZZZ-ZZZZZ", "attacker"); r != pairThrottled {
		t.Fatal("attacker should be throttled")
	}
}

func TestPairPerCodeThrottle(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p := &pairStore{now: func() time.Time { return now }}
	for i := 0; i < pairFailPerCode; i++ {
		if _, r := p.redeem("RP-AAAAA-AAAAA", fmt.Sprintf("ip%d", i)); r != pairBad {
			t.Fatalf("attempt %d: %v", i, r)
		}
	}
	if _, r := p.redeem("RP-AAAAA-AAAAA", "fresh"); r != pairThrottled {
		t.Fatal("per-code throttle not enforced")
	}
	if _, r := p.redeem("RP-BBBBB-BBBBB", "fresh"); r != pairBad {
		t.Fatal("other codes must not be affected")
	}
}

func TestPairMapsBounded(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	p := &pairStore{now: func() time.Time { return now }}
	for i := 0; i < pairFailMaxKeys+500; i++ {
		p.redeem(fmt.Sprintf("RP-%05d-%05d", i/100000, i%100000), fmt.Sprintf("c%d", i))
	}
	if len(p.fails) > pairFailMaxKeys || len(p.codes) > pairFailMaxKeys {
		t.Fatalf("maps unbounded: %d %d", len(p.fails), len(p.codes))
	}
}

func TestPairConcurrentPerIPCap(t *testing.T) {
	p := &pairStore{}
	var bad int32
	var wg sync.WaitGroup
	for i := 0; i < 100; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, r := p.redeem(fmt.Sprintf("RP-QQQQQ-%05d", i), "x"); r == pairBad {
				atomic.AddInt32(&bad, 1)
			}
		}(i)
	}
	wg.Wait()
	if bad != pairFailPerIP {
		t.Fatalf("%d failures recorded, want %d", bad, pairFailPerIP)
	}
}
