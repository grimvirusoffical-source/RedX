package host

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPresetsAllTenParseAndValidate(t *testing.T) {
	want := []string{"server", "vps", "website", "app", "game", "edge", "dev", "cluster", "backup", "all"}
	got := map[string]bool{}
	for _, p := range AllPresets() {
		got[p.Name] = true
	}
	for _, n := range want {
		if !got[n] {
			t.Errorf("preset %q missing (have %v)", n, PresetNames())
		}
	}
	if len(AllPresets()) != 10 {
		t.Errorf("want exactly 10 presets, got %d: %v", len(AllPresets()), PresetNames())
	}
	for _, p := range AllPresets() {
		p := p
		t.Run(p.Name, func(t *testing.T) {
			if p.Title == "" || p.Summary == "" || p.Audience == "" {
				t.Errorf("title/summary/audience must be filled in")
			}
			if len(p.Settings) == 0 {
				t.Fatal("no settings")
			}
			for _, k := range p.SettingKeys() {
				if strings.TrimSpace(p.Why[k]) == "" {
					t.Errorf("setting %s has no plain-English why", k)
				}
				if len(p.Why[k]) < 30 {
					t.Errorf("why for %s is too terse: %q", k, p.Why[k])
				}
			}
			for k := range p.Why {
				if _, ok := p.Settings[k]; !ok {
					t.Errorf("why given for %s which is not a setting", k)
				}
			}
			cfg := DefaultConfig()
			cfg.DataDir = t.TempDir()
			if err := p.ApplyTo(&cfg); err != nil {
				t.Fatal(err)
			}
			if cfg.Role == "follower" && len(cfg.Peers) == 0 {
				cfg.Peers = []string{"http://127.0.0.1:1"}
			}
			if cfg.TLS == "files" {
				cfg.TLSCert, cfg.TLSKey = "c", "k"
			}
			if err := cfg.Validate(); err != nil {
				t.Fatalf("preset values fail config validation: %v", err)
			}
			// every setting key is a real config key
			vals := ConfigValues(cfg)
			for _, k := range p.SettingKeys() {
				if _, ok := vals[k]; !ok {
					t.Errorf("setting %q is not a Config key", k)
				}
			}
			// diff against a config the preset was just applied to has no changes
			for _, ch := range p.Diff(cfg) {
				if ch.Changed && ch.Key != "role" {
					t.Errorf("diff after apply still shows %s changed: %v -> %v", ch.Key, ch.From, ch.To)
				}
			}
		})
	}
}

func TestPresetNoInventedNumbers(t *testing.T) {
	// Only figures measured in docs/benchmarks.md may appear as performance claims.
	for _, p := range AllPresets() {
		for k, w := range p.Why {
			for _, bad := range []string{"gentler", "x faster", "% faster", "ms latency", "times as"} {
				if strings.Contains(strings.ToLower(w), bad) {
					t.Errorf("%s.%s makes an unmeasured performance claim (%q)", p.Name, k, bad)
				}
			}
		}
	}
}

func TestPresetDiffAndUnknown(t *testing.T) {
	p, err := GetPreset("VPS")
	if err != nil {
		t.Fatal(err)
	}
	cfg := DefaultConfig()
	changed := 0
	for _, c := range p.Diff(cfg) {
		if c.Changed {
			changed++
		}
		if c.Key == "keystore_encrypt" && (!c.Changed || c.To != true) {
			t.Errorf("vps should turn keystore_encrypt on: %+v", c)
		}
	}
	if changed == 0 {
		t.Error("vps vs defaults should change something")
	}
	if _, err := GetPreset("nope"); err == nil || !strings.Contains(err.Error(), "available") {
		t.Errorf("unknown preset error should list the choices: %v", err)
	}
}

func TestPresetPrecedenceFileEnvFlag(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "redx.toml")
	if err := os.WriteFile(cfgPath, []byte("data_dir = '"+filepath.ToSlash(dir)+"'\npreset = 'website'\nrate_limit_rps = 77\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadConfig([]string{"--config", cfgPath}, func(string) string { return "" }, nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Preset != "website" || cfg.EngineDefaultTTL != 3600 {
		t.Errorf("preset values not applied: %+v", cfg.Preset)
	}
	if cfg.RateRPS != 77 {
		t.Errorf("config file must beat the preset: rps=%v", cfg.RateRPS)
	}
	// --preset overrides the file's preset
	cfg, err = LoadConfig([]string{"--config", cfgPath, "--preset", "dev"}, func(string) string { return "" }, nil)
	if err != nil || cfg.Preset != "dev" {
		t.Fatalf("flag preset: %v %v", err, cfg.Preset)
	}
}
