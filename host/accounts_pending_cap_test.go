package host

import (
	"fmt"
	"testing"
	"time"
)

// Two client addresses used to be able to sit on all 10,000 pending slots for 90 minutes.
// Expired and used sign-ins must not count, and each address has its own cap.
func TestTwoIPsCannotStarvePendingCap(t *testing.T) {
	s := newAccountStore()
	start := time.Unix(1_700_000_000, 0).UTC()
	now := start
	s.now = func() time.Time { return now }

	add := func(ip string) (string, error) {
		st := randToken("")
		err := s.addPending(st, &acctPending{clientIP: ip, verifier: "v", nonce: "n"})
		return st, err
	}
	var first []string
	for _, ip := range []string{"203.0.113.1", "203.0.113.2"} {
		for i := 0; i < acctMaxPendingPerIP; i++ {
			st, err := add(ip)
			if err != nil {
				t.Fatalf("%s sign-in %d: %v", ip, i, err)
			}
			first = append(first, st)
		}
		if _, err := add(ip); err != errTooMany {
			t.Fatalf("%s past the per-address cap: %v", ip, err)
		}
	}
	if _, err := add("203.0.113.3"); err != nil {
		t.Fatalf("a third address was starved by two full addresses: %v", err)
	}
	if live := countLive(s, now); live != acctMaxPendingPerIP*2+1 {
		t.Fatalf("live sign-ins = %d, want %d", live, acctMaxPendingPerIP*2+1)
	}

	// A finished sign-in frees its slot straight away.
	if _, kind := s.consumePending(first[0]); kind != "live" {
		t.Fatalf("consume: %s", kind)
	}
	if _, err := add("203.0.113.1"); err != nil {
		t.Fatalf("a used sign-in still counted toward the cap: %v", err)
	}

	// The cookie TTL is 30 minutes. At 89 minutes the records are still recognisable
	// as expired, and they no longer fill the cap.
	now = start.Add(89 * time.Minute)
	if kind := s.pendingKind(first[1]); kind != "expired" {
		t.Fatalf("at 89 minutes the sign-in should still be expired, got %s", kind)
	}
	for _, ip := range []string{"203.0.113.1", "203.0.113.2", "198.51.100.8"} {
		if _, err := add(ip); err != nil {
			t.Fatalf("%s at 89 minutes: %v", ip, err)
		}
	}

	// A table full of expired and used records, the old failure, does not block a new sign-in.
	now = start.Add(89 * time.Minute)
	kept := ""
	s.mu.Lock()
	s.pending = map[string]*acctPending{}
	for i := 0; i < acctMaxPending; i++ {
		st := fmt.Sprintf("oldstate%05dxxxxxxxxxxxx", i)
		if i == 1 {
			kept = st
		}
		s.pending[tokHash(st)] = &acctPending{
			created: start, consumed: i%2 == 0, clientIP: "203.0.113.1", prefix: oidcStatePrefix(st),
		}
	}
	s.mu.Unlock()
	if _, err := add("203.0.113.9"); err != nil {
		t.Fatalf("expired and used records filled the global cap: %v", err)
	}
	if _, err := add("203.0.113.1"); err != nil {
		t.Fatalf("expired records filled the per-address cap: %v", err)
	}
	now = start.Add(acctLoginTTL + acctLoginGrace + time.Minute)
	if kind := s.pendingKind(kept); kind != "unknown" {
		t.Fatalf("past the grace window the sign-in should be forgotten, got %s", kind)
	}
}

func TestPendingGlobalCapStillAppliesToLiveSignIns(t *testing.T) {
	s := newAccountStore()
	start := time.Unix(1_700_000_000, 0).UTC()
	now := start
	s.now = func() time.Time { return now }
	for i := 0; i < acctMaxPending; i++ {
		n := i / acctMaxPendingPerIP
		ip := fmt.Sprintf("10.%d.%d.%d", n>>16, (n>>8)&0xff, n&0xff)
		st := randToken("")
		if err := s.addPending(st, &acctPending{clientIP: ip, verifier: "v", nonce: "n"}); err != nil {
			t.Fatalf("live sign-in %d: %v", i, err)
		}
	}
	if err := s.addPending(randToken(""), &acctPending{clientIP: "192.0.2.9", verifier: "v", nonce: "n"}); err != errTooMany {
		t.Fatalf("live sign-ins over the global cap: %v", err)
	}
	now = start.Add(acctLoginTTL + time.Minute)
	if err := s.addPending(randToken(""), &acctPending{clientIP: "192.0.2.9", verifier: "v", nonce: "n"}); err != nil {
		t.Fatalf("sign-ins older than the cookie TTL still counted: %v", err)
	}
}

func countLive(s *accountStore, now time.Time) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	n := 0
	for _, p := range s.pending {
		if p.occupiesCap(now) {
			n++
		}
	}
	return n
}
