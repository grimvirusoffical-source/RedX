package host

import (
	"context"
	"errors"
	"fmt"
	"testing"
)

// stopping the follower loop on purpose (promote, repoint) must not leave "context canceled" as the
// last replication error.
func TestSetErrIgnoresDeliberateCancel(t *testing.T) {
	c := &Cluster{}
	c.setErr(fmt.Errorf("sync: %w", context.Canceled))
	if c.lastErr != "" {
		t.Fatalf("a cancelled loop is not an error: %q", c.lastErr)
	}
	c.setErr(errors.New("connection refused"))
	if c.lastErr == "" {
		t.Fatal("a real error must still be recorded")
	}
	c.setErr(nil)
	if c.lastErr != "" {
		t.Fatal("success clears the error")
	}
}
