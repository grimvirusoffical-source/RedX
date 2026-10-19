package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"redx/host"
	"redx/host/engineadapter"
)

func TestCLIPresetCommands(t *testing.T) {
	dir := t.TempDir()
	cfg := host.DefaultConfig()
	cfg.DataDir = dir
	cfg.ConfigFile = filepath.Join(dir, "redx.toml")
	cfg.ArgonMemKiB, cfg.ArgonTime = 64, 1
	cfg.LogLevel = "quiet"
	h, err := host.New(cfg, engineadapter.Opener(engineadapter.Config{SweepMS: 50}), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.Handler())
	t.Cleanup(func() { srv.Close(); h.Close() })
	key := h.BootstrapKey

	// ls needs no server at all and lists all ten
	out, e, code := runCLI(t, "http://127.0.0.1:1", "", "preset", "ls")
	if code != 0 {
		t.Fatalf("ls: %s", e)
	}
	for _, n := range host.PresetNames() {
		if !strings.Contains(out, n) {
			t.Errorf("ls misses %s: %s", n, out)
		}
	}
	if len(host.PresetNames()) != 10 {
		t.Errorf("want 10 presets, have %d", len(host.PresetNames()))
	}
	// show prints the plain-English why for each setting
	out, e, code = runCLI(t, "http://127.0.0.1:1", "", "preset", "show", "vps")
	if code != 0 || !strings.Contains(out, "why:") || !strings.Contains(out, "keystore_encrypt = true") || !strings.Contains(out, "REDX_KEYSTORE_PASSPHRASE") {
		t.Fatalf("show: %q %s", out, e)
	}
	if _, e, code = runCLI(t, "http://127.0.0.1:1", "", "preset", "show", "bogus"); code == 0 || !strings.Contains(e, "unknown preset") {
		t.Errorf("show bogus: %d %s", code, e)
	}
	// show --diff compares with the running host
	out, e, code = runCLI(t, srv.URL, key, "preset", "show", "website", "--diff")
	if code != 0 || !strings.Contains(out, "(now:") {
		t.Fatalf("show --diff: %q %s", out, e)
	}
	// dry run writes nothing
	out, e, code = runCLI(t, srv.URL, key, "preset", "apply", "website", "--dry-run", "--set", "rate_limit_rps=123")
	if code != 0 || !strings.Contains(out, "what changed") || !strings.Contains(out, "123") || !strings.Contains(out, "nothing written") {
		t.Fatalf("dry run: %q %s", out, e)
	}
	if _, err := os.Stat(cfg.ConfigFile); err == nil {
		t.Fatal("dry run wrote the config file")
	}
	// real apply writes preset = and the override, and says a restart is needed
	out, e, code = runCLI(t, srv.URL, key, "preset", "apply", "website", "--set", "rate_limit_rps=123")
	if code != 0 || !strings.Contains(out, "restart") {
		t.Fatalf("apply: %q %s", out, e)
	}
	b, err := os.ReadFile(cfg.ConfigFile)
	if err != nil || !strings.Contains(string(b), `preset = "website"`) || !strings.Contains(string(b), "rate_limit_rps = 123") {
		t.Fatalf("config file: %v %s", err, b)
	}
	// a read-only key may not apply
	if _, e, code = runCLI(t, srv.URL, "rx_live_nope", "preset", "apply", "website"); code == 0 {
		t.Errorf("apply with a bad key must fail: %s", e)
	}
}
