package host_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"redx/host"
)

func envMap(m map[string]string) func(string) string { return func(k string) string { return m[k] } }

func writeTOML(t *testing.T, dir, text string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "redx.toml"), []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Precedence, highest first: flags > REDX_* environment > redx.toml > preset > defaults. The default file is
// <data dir>/redx.toml for the data dir given by --data-dir, REDX_DATA_DIR or the default.
func TestConfigPrecedenceAndDataDirTOML(t *testing.T) {
	dir := t.TempDir()
	writeTOML(t, dir, "listen = \"127.0.0.1:7801\"\nlog_level = \"debug\"\nrate_limit_rps = 7\npreset = \"dev\"\n")

	// the file next to a data dir given by FLAG is read (this was ignored before 0.4.2)
	cfg, err := host.LoadConfig([]string{"--data-dir", dir}, envMap(nil), nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Listen != "127.0.0.1:7801" || cfg.LogLevel != "debug" || cfg.Preset != "dev" {
		t.Fatalf("redx.toml beside --data-dir ignored: listen=%q log=%q preset=%q", cfg.Listen, cfg.LogLevel, cfg.Preset)
	}
	// ... and given by ENV
	cfg, err = host.LoadConfig(nil, envMap(map[string]string{"REDX_DATA_DIR": dir}), nil)
	if err != nil || cfg.Listen != "127.0.0.1:7801" {
		t.Fatalf("redx.toml beside REDX_DATA_DIR ignored: %v %q", err, cfg.Listen)
	}
	// env beats the file
	cfg, _ = host.LoadConfig([]string{"--data-dir", dir}, envMap(map[string]string{"REDX_LISTEN": "127.0.0.1:7802", "REDX_LOG_LEVEL": "quiet"}), nil)
	if cfg.Listen != "127.0.0.1:7802" || cfg.LogLevel != "quiet" {
		t.Fatalf("env must beat the file: %q %q", cfg.Listen, cfg.LogLevel)
	}
	// flags beat env and file
	cfg, _ = host.LoadConfig([]string{"--data-dir", dir, "--listen", "127.0.0.1:7803"}, envMap(map[string]string{"REDX_LISTEN": "127.0.0.1:7802"}), nil)
	if cfg.Listen != "127.0.0.1:7803" {
		t.Fatalf("flag must beat env and file: %q", cfg.Listen)
	}
	// the flag data dir beats the env data dir when both name a file
	other := t.TempDir()
	writeTOML(t, other, "listen = \"127.0.0.1:7900\"\n")
	cfg, _ = host.LoadConfig([]string{"--data-dir", dir}, envMap(map[string]string{"REDX_DATA_DIR": other}), nil)
	if cfg.Listen != "127.0.0.1:7801" || cfg.DataDir != dir {
		t.Fatalf("--data-dir must win over REDX_DATA_DIR: %q %q", cfg.Listen, cfg.DataDir)
	}
	// an explicit --config replaces the data-dir file
	alt := filepath.Join(t.TempDir(), "alt.toml")
	if err := os.WriteFile(alt, []byte("listen = \"127.0.0.1:7950\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, _ = host.LoadConfig([]string{"--config", alt, "--data-dir", dir}, envMap(nil), nil)
	if cfg.Listen != "127.0.0.1:7950" {
		t.Fatalf("--config must replace the data-dir file: %q", cfg.Listen)
	}
	// the preset sits below the file: dev says one thing, the file overrides it
	if cfg.Preset != "" {
		t.Fatalf("no preset expected when only --config alt is used: %q", cfg.Preset)
	}
}

// console/CLI "Apply" writes <data dir>/redx.toml; a restart with the data dir given as a flag must pick it up.
func TestPresetApplyThenRestartTakesEffect(t *testing.T) {
	dir := t.TempDir()
	n := startNode(t, dir, nil)
	st, b, _ := do(t, "POST", n.URL+"/v1/admin/presets/game/apply", n.Key, `{"overrides":{"listen":"127.0.0.1:7811"}}`)
	if st != 200 {
		t.Fatalf("apply: %d %s", st, b)
	}
	if _, err := os.Stat(filepath.Join(dir, "redx.toml")); err != nil {
		t.Fatalf("apply wrote no redx.toml in the data dir: %v", err)
	}
	// "restart": the same command line a service would use, data dir as a flag, nothing else
	cfg, err := host.LoadConfig([]string{"--data-dir", dir}, envMap(nil), nil)
	if err != nil {
		t.Fatalf("restart config: %v", err)
	}
	if cfg.Preset != "game" || cfg.Listen != "127.0.0.1:7811" {
		t.Fatalf("applied preset not in effect after restart: preset=%q listen=%q", cfg.Preset, cfg.Listen)
	}
}

// bad values are refused before anything is written.
func TestPresetApplyRejectsBadListenBeforeWriting(t *testing.T) {
	dir := t.TempDir()
	n := startNode(t, dir, nil)
	for _, bad := range []string{`"notanaddress"`, `"127.0.0.1"`, `"127.0.0.1:99999"`, `"127.0.0.1:http"`, `":-1"`, `""`} {
		st, b, _ := do(t, "POST", n.URL+"/v1/admin/presets/game/apply", n.Key, `{"overrides":{"listen":`+bad+`}}`)
		if st != 400 || !strings.Contains(b, "listen") {
			t.Fatalf("listen=%s: want 400 naming listen, got %d %s", bad, st, b)
		}
	}
	if _, err := os.Stat(filepath.Join(dir, "redx.toml")); err == nil {
		t.Fatal("a refused apply must not write redx.toml")
	}
	st, b, _ := do(t, "POST", n.URL+"/v1/admin/presets/game/apply", n.Key, `{"overrides":{"advertise":"not a url"}}`)
	if st != 400 || !strings.Contains(b, "advertise") {
		t.Fatalf("bad advertise: %d %s", st, b)
	}
	for _, good := range []string{`"127.0.0.1:7812"`, `":7813"`, `"0.0.0.0:7777"`, `"[::1]:7814"`, `"localhost:0"`} {
		if st, b, _ := do(t, "POST", n.URL+"/v1/admin/presets/game/apply", n.Key, `{"dry_run":true,"overrides":{"listen":`+good+`}}`); st != 200 {
			t.Fatalf("listen=%s should be accepted: %d %s", good, st, b)
		}
	}
}
