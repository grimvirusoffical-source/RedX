package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strings"
	"testing"
	"time"

	"redx/host"
)

func TestStripOpenFlags(t *testing.T) {
	args, mode := stripOpenFlags([]string{"--config", "x", "--open"})
	if mode != "always" || !reflect.DeepEqual(args, []string{"--config", "x"}) {
		t.Fatalf("%v %q", args, mode)
	}
	args, mode = stripOpenFlags([]string{"--no-open", "--listen", "a"})
	if mode != "never" || len(args) != 2 {
		t.Fatalf("%v %q", args, mode)
	}
	if _, m := stripOpenFlags(nil); m != "" {
		t.Fatal(m)
	}
}

func TestConsoleURL(t *testing.T) {
	cases := map[string]string{
		"127.0.0.1:7777": "http://127.0.0.1:7777/",
		"0.0.0.0:9000":   "http://127.0.0.1:9000/",
		":8080":          "http://127.0.0.1:8080/",
		"[::1]:7777":     "http://[::1]:7777/",
	}
	for listen, want := range cases {
		cfg := host.DefaultConfig()
		cfg.Listen, cfg.TLS = listen, "off"
		if got := consoleURL(cfg); got != want {
			t.Errorf("%s: %s want %s", listen, got, want)
		}
	}
	cfg := host.DefaultConfig()
	cfg.Listen, cfg.TLS = "127.0.0.1:7777", "auto"
	if got := consoleURL(cfg); got != "https://127.0.0.1:7777/" {
		t.Error(got)
	}
}

func TestShouldOpenRules(t *testing.T) {
	cfg := host.DefaultConfig()
	cfg.DataDir = t.TempDir()
	old := autoOpen
	defer func() { autoOpen = old }()

	autoOpen = false
	if shouldOpen(cfg, "always", true) {
		t.Error("a non-foreground run (service, test) must never open a browser")
	}
	autoOpen = true
	t.Setenv("REDX_NO_OPEN", "1")
	if shouldOpen(cfg, "always", true) {
		t.Error("REDX_NO_OPEN must win, even over --open")
	}
	t.Setenv("REDX_NO_OPEN", "")
	if shouldOpen(cfg, "never", true) {
		t.Error("--no-open")
	}
	if !shouldOpen(cfg, "always", false) {
		t.Error("--open forces it")
	}
	t.Setenv("CI", "1") // headless
	if shouldOpen(cfg, "", true) {
		t.Error("headless machines never auto-open")
	}
	t.Setenv("CI", "")
	t.Setenv("SSH_CONNECTION", "")
	t.Setenv("SSH_TTY", "")
	t.Setenv("DISPLAY", ":0")
	t.Setenv("WAYLAND_DISPLAY", "")
	if !shouldOpen(cfg, "", true) {
		t.Skip("environment looks headless on this OS")
	}
	if shouldOpen(cfg, "", false) {
		t.Error("after the first open the browser is not launched again")
	}
	if _, err := os.Stat(filepath.Join(cfg.DataDir, "console.opened")); err != nil {
		t.Error("marker missing")
	}
}

// startPlain runs runDaemon with an arbitrary config and waits for /healthz on http or https.
func startPlain(t *testing.T, cfgText string, extraArgs ...string) (base string, out *strings.Builder, stop func() error) {
	t.Helper()
	dir := t.TempDir()
	addr := freeAddr(t)
	cfgPath := filepath.Join(dir, "redx.toml")
	writeFile(t, cfgPath, "data_dir = '"+filepath.ToSlash(dir)+"'\nlisten = '"+addr+"'\nlog_level = 'quiet'\nargon_memory_kib = 64\nargon_time = 1\n"+cfgText)
	rd, wr, _ := os.Pipe()
	oldOut := os.Stdout
	os.Stdout = wr
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- runDaemon(ctx, append([]string{"--config", cfgPath}, extraArgs...), func(string) {})
	}()
	captured := make(chan string, 1)
	go func() { b, _ := io.ReadAll(rd); captured <- string(b) }()
	client := &http.Client{Timeout: 2 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	up := ""
	for i := 0; i < 200 && up == ""; i++ {
		select {
		case err := <-done:
			os.Stdout = oldOut
			wr.Close()
			t.Fatalf("daemon exited early: %v (%s)", err, <-captured)
		default:
		}
		for _, scheme := range []string{"https", "http"} {
			if resp, err := client.Get(scheme + "://" + addr + "/healthz"); err == nil {
				resp.Body.Close()
				if resp.StatusCode == 200 {
					up = scheme + "://" + addr
					break
				}
			}
		}
		if up == "" {
			time.Sleep(50 * time.Millisecond)
		}
	}
	os.Stdout = oldOut
	wr.Close()
	text := <-captured
	if up == "" {
		cancel()
		t.Fatalf("daemon did not come up: %s", text)
	}
	sb := &strings.Builder{}
	sb.WriteString(text)
	return up, sb, func() error {
		cancel()
		select {
		case err := <-done:
			return err
		case <-time.After(15 * time.Second):
			return context.DeadlineExceeded
		}
	}
}

func insecureGet(t *testing.T, url string, hdr ...string) (int, string, http.Header) {
	t.Helper()
	client := &http.Client{Timeout: 3 * time.Second, Transport: &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: true}}}
	req, _ := http.NewRequest("GET", url, nil)
	for i := 0; i+1 < len(hdr); i += 2 {
		req.Header.Set(hdr[i], hdr[i+1])
	}
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, string(b), resp.Header
}

// Every preset must start a real redxd (the preset's own values, with only the listen address,
// cost knobs and log level overridden from the config file) and serve the console.
func TestEveryPresetStartsARealDaemon(t *testing.T) {
	for _, p := range host.AllPresets() {
		p := p
		t.Run(p.Name, func(t *testing.T) {
			extra := "preset = '" + p.Name + "'\nbootstrap = 'console'\n"
			pc := host.DefaultConfig()
			_ = p.ApplyTo(&pc)
			if pc.Role == "follower" {
				extra += "peers = ['http://127.0.0.1:1']\n"
			}
			if pc.KeystoreEnc {
				t.Setenv("REDX_KEYSTORE_PASSPHRASE", "preset-test-passphrase")
			}
			if pc.TLS == "files" {
				t.Skip("tls=files needs certificates")
			}
			base, out, stop := startPlain(t, extra)
			key := regexp.MustCompile(`rx_live_[A-Za-z0-9_-]+`).FindString(out.String())
			if key == "" && pc.Role != "follower" {
				t.Errorf("preset %s: console bootstrap printed no key", p.Name)
			}
			st, body, hdr := insecureGet(t, base+"/")
			if st != 200 || !strings.Contains(body, "<title>") || hdr.Get("X-Frame-Options") != "DENY" {
				t.Errorf("console not served: %d %v", st, hdr)
			}
			if key != "" {
				st, body, _ = insecureGet(t, base+"/v1/admin/status", "Authorization", "Bearer "+key)
				if st != 200 {
					t.Errorf("admin status %d %s", st, body)
				}
				var cfgResp struct {
					Config map[string]interface{} `json:"config"`
				}
				st, body, _ = insecureGet(t, base+"/v1/admin/config", "Authorization", "Bearer "+key)
				if st != 200 || json.Unmarshal([]byte(body), &cfgResp) != nil {
					t.Fatalf("config %d %s", st, body)
				}
				if got := cfgResp.Config["preset"]; got != p.Name {
					t.Errorf("effective config preset = %v want %s", got, p.Name)
				}
				if v, ok := p.Settings["engine_durability"]; ok && cfgResp.Config["engine_durability"] != v {
					t.Errorf("engine_durability = %v want %v", cfgResp.Config["engine_durability"], v)
				}
			}
			if err := stop(); err != nil {
				t.Errorf("shutdown: %v", err)
			}
		})
	}
}

func TestPresetFlagAndUnknownPreset(t *testing.T) {
	base, out, stop := startPlain(t, "tls = 'off'\nbootstrap = 'console'\n", "--preset", "website")
	key := regexp.MustCompile(`rx_live_[A-Za-z0-9_-]+`).FindString(out.String())
	_, body, _ := insecureGet(t, base+"/v1/admin/config", "Authorization", "Bearer "+key)
	if !strings.Contains(body, `"preset":"website"`) || !strings.Contains(body, `"engine_default_ttl":3600`) {
		t.Errorf("--preset not applied: %s", body)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "redx.toml")
	writeFile(t, cfgPath, "data_dir = '"+filepath.ToSlash(dir)+"'\npreset = 'nonsense'\n")
	err := runDaemon(context.Background(), []string{"--config", cfgPath}, func(string) {})
	if err == nil || !strings.Contains(err.Error(), "unknown preset") {
		t.Fatalf("unknown preset must fail clearly: %v", err)
	}
}

// bootstrap = 'web': nothing is printed to stdout, the console offers key creation exactly once.
func TestWebBootstrapThroughDaemon(t *testing.T) {
	base, out, stop := startPlain(t, "tls = 'off'\nbootstrap = 'web'\n")
	if regexp.MustCompile(`rx_live_`).MatchString(out.String()) {
		t.Fatalf("web bootstrap leaked a key to stdout: %s", out.String())
	}
	st, body, _ := insecureGet(t, base+"/v1/ui/bootstrap-status")
	if st != 200 || !strings.Contains(body, `"needsSetup":true`) {
		t.Fatalf("bootstrap-status: %d %s", st, body)
	}
	if err := stop(); err != nil {
		t.Fatal(err)
	}
	t.Setenv("REDX_NO_BOOTSTRAP", "1")
	base, _, stop = startPlain(t, "tls = 'off'\nbootstrap = 'web'\n")
	_, body, _ = insecureGet(t, base+"/v1/ui/bootstrap-status")
	if strings.Contains(body, `"needsSetup":true`) {
		t.Errorf("REDX_NO_BOOTSTRAP=1 must disable the web bootstrap: %s", body)
	}
	_ = stop()
}
