package host

import (
	"fmt"
	"testing"
	"time"
)

// An attacker failing from many addresses must not be able to clear an existing block.
func TestFailTrackerCannotBeFlushed(t *testing.T) {
	f := newFailTracker(3, time.Minute)
	for i := 0; i < 3; i++ {
		f.record("203.0.113.9")
	}
	if f.blocked("203.0.113.9") == 0 {
		t.Fatal("victim IP should be blocked")
	}
	for i := 0; i < failTrackerCap+500; i++ {
		f.record(fmt.Sprintf("10.%d.%d.%d", i>>16&255, i>>8&255, i&255))
	}
	if f.blocked("203.0.113.9") == 0 {
		t.Fatal("block was flushed by filling the table")
	}
}

// Rotating addresses inside one IPv6 /64 counts as one client.
func TestFailTrackerIPv6Slash64(t *testing.T) {
	f := newFailTracker(3, time.Minute)
	for i := 1; i <= 3; i++ {
		f.record(fmt.Sprintf("2001:db8:1:2::%x", i))
	}
	if f.blocked("2001:db8:1:2::ffff") == 0 {
		t.Fatal("same /64 should share the failure budget")
	}
	if f.blocked("2001:db8:1:3::1") != 0 {
		t.Fatal("different /64 must not be blocked")
	}
}
