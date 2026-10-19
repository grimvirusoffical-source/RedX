package main

import (
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"redx/host"
	"redx/host/engineadapter"
)

// `key list --json` shows rate limits and `key rotate --json` prints JSON.
func TestKeyListShowsRateLimitsAndRotateHonoursJSON(t *testing.T) {
	cfg := host.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.ArgonMemKiB, cfg.ArgonTime = 64, 1
	cfg.LogLevel = "quiet"
	h, err := host.New(cfg, engineadapter.Opener(engineadapter.Config{SweepMS: 50}), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.Handler())
	t.Cleanup(func() { srv.Close(); h.Close() })

	out, errs, code := runCLI(t, srv.URL, h.BootstrapKey, "key", "create", "--json", "--scope", "read", "--db", "default", "--label", "rl", "--rate-rps", "5", "--rate-burst", "7")
	if code != 0 {
		t.Fatalf("key create: %d %s %s", code, out, errs)
	}
	var created struct {
		Info map[string]interface{} `json:"info"`
		ID   string                 `json:"id"`
	}
	_ = json.Unmarshal([]byte(out), &created)
	id := created.ID
	if id == "" {
		if v, ok := created.Info["id"].(string); ok {
			id = v
		}
	}
	if id == "" {
		t.Fatalf("no key id in %s", out)
	}
	list, _, _ := runCLI(t, srv.URL, h.BootstrapKey, "key", "list", "--json")
	if !strings.Contains(list, `"rate_rps":5`) || !strings.Contains(list, `"rate_burst":7`) {
		t.Fatalf("key list --json lacks the rate limits: %s", list)
	}
	rot, errs, code := runCLI(t, srv.URL, h.BootstrapKey, "key", "rotate", id, "--json")
	var r struct{ Key, ID, Replaces string }
	if code != 0 || json.Unmarshal([]byte(rot), &r) != nil || !strings.HasPrefix(r.Key, "rx_") || r.Replaces != id {
		t.Fatalf("key rotate --json must print JSON: code=%d out=%q err=%q", code, rot, errs)
	}
}
