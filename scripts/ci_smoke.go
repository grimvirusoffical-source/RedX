//go:build ignore

// ci_smoke is the cross-platform smoke test run by CI on Linux, Windows and macOS (no bash, curl or python needed).
//
//	go run scripts/ci_smoke.go <bindir>
//
// It creates a throw-away data dir, makes an admin key offline, starts redxd, then uses the redx CLI to
// set/get a value, let a TTL expire, run a BoxQL query, receive a subscribe event, kill the host hard,
// restart it and check the data survived, and finally stop it. The key is never printed.
package main

import (
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"
)

var (
	bin, dataDir, addr, adminKey string
	failures                     int
)

func ok(format string, a ...any) { fmt.Printf("PASS  "+format+"\n", a...) }
func bad(format string, a ...any) {
	failures++
	fmt.Printf("FAIL  "+format+"\n", a...)
}

func exe(name string) string {
	if runtime.GOOS == "windows" {
		return filepath.Join(bin, name+".exe")
	}
	return filepath.Join(bin, name)
}

func freePort() string {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic(err)
	}
	defer l.Close()
	return fmt.Sprint(l.Addr().(*net.TCPAddr).Port)
}

// cli runs `redx args...` against the host and returns combined output and exit status.
func cli(args ...string) (string, error) {
	cmd := exec.Command(exe("redx"), args...)
	cmd.Env = append(os.Environ(), "REDX_ADDR=http://"+addr, "REDX_KEY="+adminKey)
	var b bytes.Buffer
	cmd.Stdout, cmd.Stderr = &b, &b
	err := cmd.Run()
	return b.String(), err
}

type host struct {
	cmd *exec.Cmd
	out *bytes.Buffer
	mu  sync.Mutex
}

func startHost() *host {
	h := &host{out: &bytes.Buffer{}}
	h.cmd = exec.Command(exe("redxd"), "run", "--data-dir", dataDir, "--listen", addr, "--no-open", "--bootstrap", "console")
	h.cmd.Env = append(os.Environ(), "REDX_NO_OPEN=1")
	h.cmd.Stdout, h.cmd.Stderr = h.out, h.out
	if err := h.cmd.Start(); err != nil {
		fmt.Println("cannot start redxd:", err)
		os.Exit(1)
	}
	for i := 0; i < 150; i++ {
		if r, err := http.Get("http://" + addr + "/healthz"); err == nil {
			r.Body.Close()
			if r.StatusCode == 200 {
				return h
			}
		}
		time.Sleep(200 * time.Millisecond)
	}
	fmt.Println("redxd did not become healthy; output:\n" + scrub(h.out.String()))
	_ = h.cmd.Process.Kill()
	os.Exit(1)
	return nil
}

func scrub(s string) string {
	return regexp.MustCompile(`rx_[a-z]+_[0-9A-Za-z]+`).ReplaceAllString(s, "rx_***")
}

func (h *host) kill() { _ = h.cmd.Process.Kill(); _, _ = h.cmd.Process.Wait() }

func post(url, key, body string) (int, string) {
	req, _ := http.NewRequest("POST", url, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	if key != "" {
		req.Header.Set("Authorization", "Bearer "+key)
	}
	// Dangerous ops need X-RedX-Confirm (server-enforced since 0.4.5).
	switch {
	case strings.HasSuffix(req.URL.Path, "/v1/keys/pairing"):
		req.Header.Set("X-RedX-Confirm", "createPairingCode")
	case req.URL.Path == "/v1/keys" || strings.HasSuffix(req.URL.Path, "/v1/keys"):
		req.Header.Set("X-RedX-Confirm", "createKey")
	case strings.HasSuffix(req.URL.Path, "/v1/cluster/promote"):
		req.Header.Set("X-RedX-Confirm", "promote")
	case strings.HasSuffix(req.URL.Path, "/v1/cluster/join-token"):
		req.Header.Set("X-RedX-Confirm", "createJoinToken")
	case strings.HasSuffix(req.URL.Path, "/v1/connect/approve"):
		req.Header.Set("X-RedX-Confirm", "connectApprove")
	}
	r, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, err.Error()
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return r.StatusCode, string(b)
}

func smokeLauncher() {
	dir, _ := os.MkdirTemp("", "redx-launch-")
	defer os.RemoveAll(dir)
	la := "127.0.0.1:" + freePort()
	cmd := exec.Command(exe("redx-launcher"))
	cmd.Env = append(os.Environ(), "REDX_LISTEN="+la, "REDX_DATA_DIR="+dir, "REDX_LAUNCHER_NO_OPEN=1", "REDX_NO_OPEN=1", "REDX_LAUNCHER_PIDFILE="+filepath.Join(dir, "launcher.pid"))
	out, err := cmd.CombinedOutput()
	if err != nil || !strings.Contains(string(out), "http://"+la+"/") {
		bad("launcher: %v %q", err, out)
		return
	}
	code, body := get("http://" + la + "/v1/ui/bootstrap-status")
	defer func() { // stop the detached host the launcher started
		if b, err := os.ReadFile(filepath.Join(dir, "launcher.pid")); err == nil {
			if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil {
				if p, err := os.FindProcess(pid); err == nil {
					_ = p.Kill()
					time.Sleep(500 * time.Millisecond)
				}
			}
		}
	}()
	if code != 200 || !strings.Contains(body, `"needsSetup":true`) {
		bad("launcher host is up but first-run setup is not offered: %d %s", code, body)
		return
	}
	ok("launcher started a hidden host; the console offers first-run setup (no terminal)")
}

func get(url string) (int, string) {
	r, err := http.Get(url)
	if err != nil {
		return 0, err.Error()
	}
	defer r.Body.Close()
	b, _ := io.ReadAll(r.Body)
	return r.StatusCode, string(b)
}

func main() {
	if len(os.Args) < 2 {
		fmt.Println("usage: go run scripts/ci_smoke.go <bindir>")
		os.Exit(2)
	}
	bin, _ = filepath.Abs(os.Args[1])
	var err error
	dataDir, err = os.MkdirTemp("", "redx-smoke-")
	if err != nil {
		panic(err)
	}
	defer os.RemoveAll(dataDir)
	addr = "127.0.0.1:" + freePort()

	for _, v := range []string{"redxd", "redx"} {
		out, err := exec.Command(exe(v), "--version").CombinedOutput()
		if err != nil || !strings.HasPrefix(string(out), v+" ") {
			bad("%s --version: %v %q", v, err, out)
		} else {
			ok("%s", strings.TrimSpace(string(out)))
		}
	}

	// admin key created offline (the console flow is covered by Go tests); parsed from --json output, never printed
	cmd := exec.Command(exe("redx"), "key", "create", "--offline", "--data-dir", dataDir, "--scope", "admin", "--db", "*", "--label", "ci", "--json")
	kb, err := cmd.Output()
	m := regexp.MustCompile(`rx_live_[0-9A-Za-z]+`).Find(kb)
	if err != nil || m == nil {
		bad("offline admin key: %v", err)
		os.Exit(1)
	}
	adminKey = string(m)
	ok("offline admin key created (not printed)")

	h := startHost()
	ok("redxd healthy on %s", addr)

	if code, _ := get("http://" + addr + "/"); code == 200 {
		ok("web console served at /")
	} else {
		bad("console / returned %d", code)
	}
	if code, _ := get("http://" + addr + "/v1/path/x.red-xai.db:Box%5BID=1%5D"); code == 401 {
		ok("unauthenticated API call is 401")
	} else {
		bad("unauthenticated API call returned %d", code)
	}

	path := "smoke.red-xai.db:Player[ID=1].Name"
	if out, err := cli("set", path, `"Ann"`); err != nil {
		bad("set: %v %s", err, out)
	} else if out, err := cli("get", path); err != nil || !strings.Contains(out, "Ann") {
		bad("get: %v %s", err, out)
	} else {
		ok("set/get round trip")
	}

	// one-time pairing code: issued by an admin, redeemed with no key, works once; the code is not a key
	if code, body := post("http://"+addr+"/v1/keys/pairing", adminKey, `{"db":"default","scope":"read","label":"smoke-phone"}`); code != 201 {
		bad("issue pairing code: %d %s", code, scrub(body))
	} else if pc := regexp.MustCompile(`RP-[A-Z2-9]{5}-[A-Z2-9]{5}`).FindString(body); pc == "" || strings.Contains(body, "rx_live_") {
		bad("pairing reply malformed: %s", scrub(body))
	} else if code, body := post("http://"+addr+"/v1/pair/exchange", "", `{"code":"`+pc+`"}`); code != 201 || !strings.Contains(body, "rx_live_") {
		bad("redeem pairing code: %d %s", code, scrub(body))
	} else if code, _ := post("http://"+addr+"/v1/pair/exchange", "", `{"code":"`+pc+`"}`); code != 401 {
		bad("a used pairing code must be rejected, got %d", code)
	} else {
		ok("pairing code: issued, redeemed once for a key, second use rejected")
	}

	// one-click launcher: starts a hidden host on a fresh data dir and the console offers first-run setup (no terminal)
	if _, err := os.Stat(exe("redx-launcher")); err == nil {
		smokeLauncher()
	} else {
		fmt.Println("SKIP  redx-launcher not in", bin)
	}

	// expiry
	tpath := "cache.red-xai-db-qs-ls:Session[ID=9].Temp"
	if out, err := cli("set", tpath, `"gone soon"`, "--ttl", "1"); err != nil {
		bad("set --ttl: %v %s", err, out)
	} else if out, _ := cli("get", tpath); !strings.Contains(out, "gone soon") {
		bad("value with ttl not readable before expiry: %s", out)
	} else {
		time.Sleep(2500 * time.Millisecond)
		if out, err := cli("get", tpath); err == nil && strings.Contains(out, "gone soon") {
			bad("value still readable after ttl: %s", out)
		} else {
			ok("TTL expiry hides the value")
		}
	}

	// BoxQL
	if out, err := cli("set", "smoke.red-xai.db:Player[ID=2]", `[ {Name[]} = "Bob", {Level[]} = 30 ]`); err != nil {
		bad("set box: %v %s", err, out)
	}
	if out, err := cli("bx", `{Get[]} = smoke:Player[Level > $n] -> Name`, "--param", "n=10"); err != nil || !strings.Contains(out, "Bob") {
		bad("BoxQL query: %v %s", err, out)
	} else {
		ok("BoxQL query with a $parameter")
	}

	// subscribe: start the stream, then write, expect an event
	sub := exec.Command(exe("redx"), "subscribe", "smoke.red-xai.db:Player[ID=2]")
	sub.Env = append(os.Environ(), "REDX_ADDR=http://"+addr, "REDX_KEY="+adminKey)
	var sb syncBuf
	sub.Stdout, sub.Stderr = &sb, &sb
	if err := sub.Start(); err != nil {
		bad("subscribe start: %v", err)
	} else {
		time.Sleep(1500 * time.Millisecond)
		_, _ = cli("set", "smoke.red-xai.db:Player[ID=2].Level", "31")
		got := false
		for i := 0; i < 50 && !got; i++ {
			got = strings.Contains(sb.String(), `"op"`)
			time.Sleep(200 * time.Millisecond)
		}
		_ = sub.Process.Kill()
		_, _ = sub.Process.Wait()
		if got {
			ok("subscribe delivered a change event")
		} else {
			bad("subscribe received nothing: %q", sb.String())
		}
	}

	// hard kill + restart: committed data must survive
	h.kill()
	ok("host killed hard")
	h = startHost()
	if out, err := cli("get", path); err != nil || !strings.Contains(out, "Ann") {
		bad("data lost after hard kill: %v %s", err, out)
	} else {
		ok("data survived a hard kill + restart")
	}
	h.kill()

	if strings.Contains(h.out.String(), adminKey) {
		bad("admin key appeared in the host output")
	} else {
		ok("admin key never appeared in host output")
	}
	if failures > 0 {
		fmt.Printf("\n%d check(s) FAILED\n", failures)
		os.Exit(1)
	}
	fmt.Println("\nall smoke checks passed on", runtime.GOOS+"/"+runtime.GOARCH)
}

type syncBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *syncBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }
