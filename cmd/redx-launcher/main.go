// Command redx-launcher is the one-click entry point used by the Windows Start-menu shortcut and the
// macOS RedX.app. It needs no terminal: if the RedX host on this machine is not answering, it starts
// redxd in the background (no console window), waits until it is healthy, then opens the web console
// in the default browser. The very first start shows the one-time admin key inside the console.
//
// It only uses the standard library and never reads or prints secrets.
package main

import (
	"fmt"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

const defaultAddr = "127.0.0.1:7777"

// version is stamped by the build scripts: -X main.version=X.Y.Z
var version = "dev"

const usage = `redx-launcher: starts the RedX host on this machine if it is not running and opens the console.

usage: redx-launcher            start (if needed) and open the console
       redx-launcher --version  print the version and exit
       redx-launcher -h         this help

Environment: REDX_LISTEN (default 127.0.0.1:7777), REDX_LAUNCHER_NO_OPEN=1 (do not open a browser).
`

// parseArgs decides what to do with the command line. It never starts anything itself.
// macOS may pass a -psn_... argument when the app is opened from Finder; it is ignored.
func parseArgs(args []string) (action string, out string, code int) {
	for _, a := range args {
		switch {
		case a == "--version" || a == "-version" || a == "-v" || a == "version":
			return "exit", fmt.Sprintf("redx-launcher %s (%s/%s)\n", version, runtime.GOOS, runtime.GOARCH), 0
		case a == "-h" || a == "--help" || a == "-help" || a == "help":
			return "exit", usage, 0
		case strings.HasPrefix(a, "-psn_"):
		default:
			return "exit", "redx-launcher: unknown argument " + strconv.Quote(a) + "\n\n" + usage, 2
		}
	}
	return "run", "", 0
}

func main() {
	if action, out, code := parseArgs(os.Args[1:]); action == "exit" {
		if code == 0 {
			fmt.Print(out)
		} else {
			fmt.Fprint(os.Stderr, out)
		}
		if runtime.GOOS == "windows" { // a GUI program has no console to print to
			showMessage("RedX", strings.TrimSpace(out))
		}
		os.Exit(code)
	}
	addr := os.Getenv("REDX_LISTEN")
	if addr == "" {
		addr = defaultAddr
	}
	if h, p, err := net.SplitHostPort(addr); err == nil && (h == "" || h == "0.0.0.0" || h == "::" || h == "[::]") {
		addr = net.JoinHostPort("127.0.0.1", p)
	}
	base := "http://" + addr
	if !healthy(base) {
		if err := startHost(); err != nil {
			fail("RedX could not start its host: " + err.Error())
			return
		}
		deadline := time.Now().Add(30 * time.Second)
		for !healthy(base) {
			if time.Now().After(deadline) {
				fail("RedX started but did not answer on " + base + " within 30 seconds. Run redxd.exe from a terminal to see the error.")
				return
			}
			time.Sleep(250 * time.Millisecond)
		}
	}
	if os.Getenv("REDX_LAUNCHER_NO_OPEN") != "" { // used by tests and CI: do not start a browser
		fmt.Println(base + "/")
		return
	}
	if err := openURL(base + "/"); err != nil {
		fail("RedX is running. Open " + base + "/ in your browser.")
	}
}

func healthy(base string) bool {
	c := http.Client{Timeout: 800 * time.Millisecond}
	r, err := c.Get(base + "/healthz")
	if err != nil {
		return false
	}
	r.Body.Close()
	return r.StatusCode == 200
}

// startHost launches redxd (next to this program) detached from the launcher.
func startHost() error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	name := "redxd"
	if runtime.GOOS == "windows" {
		name += ".exe"
	}
	dir := filepath.Dir(exe)
	cand := []string{filepath.Join(dir, name), filepath.Join(dir, "..", "bin", name), filepath.Join(dir, "..", "Resources", name)}
	var bin string
	for _, c := range cand {
		if st, err := os.Stat(c); err == nil && !st.IsDir() {
			bin = c
			break
		}
	}
	if bin == "" {
		return fmt.Errorf("%s not found next to the launcher", name)
	}
	// --open: the host itself opens the console once it is up (first run); the launcher also opens it
	// below when the host was already running. REDX_NO_OPEN is honoured by redxd.
	cmd := exec.Command(bin, "run", "--no-open")
	detach(cmd)
	if err := cmd.Start(); err != nil {
		return err
	}
	if pf := os.Getenv("REDX_LAUNCHER_PIDFILE"); pf != "" { // test hook: lets CI stop the detached host
		_ = os.WriteFile(pf, []byte(fmt.Sprint(cmd.Process.Pid)), 0o600)
	}
	return cmd.Process.Release()
}

func openURL(u string) error {
	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", u)
	case "darwin":
		cmd = exec.Command("open", u)
	default:
		cmd = exec.Command("xdg-open", u)
	}
	return cmd.Start()
}

func fail(msg string) {
	fmt.Fprintln(os.Stderr, msg)
	showMessage("RedX", msg)
	os.Exit(1)
}
