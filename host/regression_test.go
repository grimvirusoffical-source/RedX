package host_test

import (
	"errors"
	"strings"
	"testing"

	"redx/host"
)

// a non-numeric ttl or checkpoint is a clear 400, not silently ignored.
func TestPutRejectsNonNumericTTL(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	for _, q := range []string{"ttl=abc", "ttl=1.5", "ttl=60s", "checkpoint=x"} {
		st, b, _ := do(t, "PUT", n.URL+P+"s.red-xai-db-qs:Q.A?"+q, n.Key, `1`)
		if st != 400 {
			t.Fatalf("?%s: want 400 got %d %s", q, st, b)
		}
		if !strings.Contains(b, "invalid ") || !strings.Contains(b, "whole number of seconds") {
			t.Fatalf("?%s: message not clear: %s", q, b)
		}
	}
	// a valid ttl is still accepted
	if st, b, _ := do(t, "PUT", n.URL+P+"s.red-xai-db-qs:Q.A?ttl=60", n.Key, `1`); st != 200 {
		t.Fatalf("valid ttl rejected: %d %s", st, b)
	}
}

// with no REDX_* override set, env_overrides is [] (not null); the Settings page calls .length on it.
func TestAdminConfigEnvOverridesIsEmptyArrayNotNull(t *testing.T) {
	for _, k := range []string{"REDX_DATA_DIR", "REDX_LISTEN", "REDX_ROLE", "REDX_TLS", "REDX_PRESET", "REDX_LOG_LEVEL"} {
		t.Setenv(k, "") // empty counts as unset
	}
	n := startNode(t, t.TempDir(), nil)
	st, b, _ := do(t, "GET", n.URL+"/v1/admin/config", n.Key, "")
	if st != 200 {
		t.Fatalf("config: %d %s", st, b)
	}
	if !strings.Contains(b, `"env_overrides":[]`) || strings.Contains(b, `"env_overrides":null`) {
		t.Fatalf("env_overrides must be [] : %s", b)
	}
}

// a negative ttl gets its own clear message.
func TestPutNegativeTTLMessage(t *testing.T) {
	n := startNode(t, t.TempDir(), nil)
	st, b, _ := do(t, "PUT", n.URL+P+"s.red-xai-db-qs:Q.A?ttl=-5", n.Key, `1`)
	if st != 400 || !strings.Contains(b, "invalid ttl -5") || strings.Contains(b, "ttl/checkpoint") {
		t.Fatalf("negative ttl: %d %s", st, b)
	}
}

func TestJoinErrorHintOnlyForCodeProblems(t *testing.T) {
	if h := host.JoinErrorHint(errors.New("join code is not valid")); !strings.Contains(h, "10 minutes") {
		t.Fatalf("code problem needs the hint: %q", h)
	}
	for _, m := range []string{"certificate fingerprint does not match the pin", "x509: certificate signed by unknown authority", "dial tcp: connection refused"} {
		if h := host.JoinErrorHint(errors.New(m)); h != "" {
			t.Fatalf("%q must not get the code-expiry hint: %q", m, h)
		}
	}
}
