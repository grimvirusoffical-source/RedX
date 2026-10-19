package main

import (
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestParseArgs(t *testing.T) {
	for _, c := range []struct {
		args   []string
		action string
		code   int
		has    string
	}{
		{nil, "run", 0, ""},
		{[]string{"-psn_0_12345"}, "run", 0, ""}, // macOS Finder
		{[]string{"--version"}, "exit", 0, "redx-launcher dev"},
		{[]string{"-h"}, "exit", 0, "usage:"},
		{[]string{"--help"}, "exit", 0, "usage:"},
		{[]string{"--bogus"}, "exit", 2, "unknown argument"},
	} {
		a, out, code := parseArgs(c.args)
		if a != c.action || code != c.code || !strings.Contains(out, c.has) {
			t.Fatalf("%v: got %s %d %q", c.args, a, code, out)
		}
	}
}

// --version and -h must exit without starting a host (and the build stamps the version).
func TestVersionAndHelpNeverStartTheHost(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows launcher shows a message box for --version/-h; parseArgs is covered above")
	}
	dir := t.TempDir()
	bin := filepath.Join(dir, "redx-launcher")
	if out, err := exec.Command("go", "build", "-ldflags", "-X main.version=9.8.7", "-o", bin, ".").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	// a fake redxd next to the launcher that would leave a marker if it were started
	marker := filepath.Join(dir, "started")
	os.WriteFile(filepath.Join(dir, "redxd"), []byte("#!/bin/sh\ntouch '"+marker+"'\n"), 0o755)
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	addr := ln.Addr().String()
	ln.Close()
	for _, arg := range []string{"--version", "-h", "--nope"} {
		cmd := exec.Command(bin, arg)
		cmd.Env = append(os.Environ(), "REDX_LISTEN="+addr, "REDX_LAUNCHER_NO_OPEN=1", "HOME="+dir)
		out, _ := cmd.CombinedOutput()
		if arg == "--version" && !strings.Contains(string(out), "redx-launcher 9.8.7") {
			t.Fatalf("--version: %q", out)
		}
		time.Sleep(100 * time.Millisecond)
		if _, err := os.Stat(marker); err == nil {
			t.Fatalf("%s started redxd", arg)
		}
		if r, err := (&http.Client{Timeout: 300 * time.Millisecond}).Get("http://" + addr + "/healthz"); err == nil {
			r.Body.Close()
			t.Fatalf("%s: something answers on %s", arg, addr)
		}
	}
}
