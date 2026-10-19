package main

import (
	"bufio"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"testing"
	"time"
)

// TestCABI builds the shared library, compiles testdata/redx_test.c against include/redx.h and runs it
// against a real redxd (REDXD_BIN, or built from the repository). Needs a C compiler; skipped on Windows.
func TestCABI(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the C test program is built on Linux and macOS")
	}
	cc := os.Getenv("CC")
	if cc == "" {
		cc = "cc"
	}
	if _, err := exec.LookPath(cc); err != nil {
		t.Skip("no C compiler")
	}
	dir := t.TempDir()
	lib := filepath.Join(dir, "libredx.so")
	if runtime.GOOS == "darwin" {
		lib = filepath.Join(dir, "libredx.dylib")
	}
	run(t, "", "go", "build", "-buildmode=c-shared", "-o", lib, ".")
	exe := filepath.Join(dir, "redx_test")
	run(t, "", cc, "-Wall", "-Werror", "-Iinclude", "-o", exe, "testdata/redx_test.c", "-L"+dir, "-lredx", "-Wl,-rpath,"+dir)

	bin := os.Getenv("REDXD_BIN")
	if bin == "" {
		bin = filepath.Join(dir, "redxd")
		run(t, filepath.Join("..", "..", ".."), "go", "build", "-o", bin, "./cmd/redxd")
	}
	l, _ := net.Listen("tcp", "127.0.0.1:0")
	port := l.Addr().(*net.TCPAddr).Port
	l.Close()
	url := "http://127.0.0.1:" + strconv.Itoa(port)
	host := exec.Command(bin, "run", "--no-open", "--bootstrap", "console", "--data-dir", filepath.Join(dir, "data"), "--listen", "127.0.0.1:"+strconv.Itoa(port))
	host.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + dir}
	stdout, _ := host.StdoutPipe()
	if err := host.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = host.Process.Kill(); _, _ = host.Process.Wait() }()
	keyCh := make(chan string, 1)
	go func() {
		re := regexp.MustCompile(`rx_live_[A-Za-z0-9]{43}`)
		sc := bufio.NewScanner(stdout)
		for sc.Scan() {
			if m := re.FindString(sc.Text()); m != "" {
				keyCh <- m
				break
			}
		}
		for sc.Scan() {
		}
	}()
	var key string
	select {
	case key = <-keyCh:
	case <-time.After(20 * time.Second):
		t.Fatal("no bootstrap key")
	}
	for i := 0; ; i++ {
		if res, err := http.Get(url + "/healthz"); err == nil && res.StatusCode == 200 {
			res.Body.Close()
			break
		}
		if i > 200 {
			t.Fatal("redxd not ready")
		}
		time.Sleep(50 * time.Millisecond)
	}
	cmd := exec.Command(exe)
	cmd.Env = append(os.Environ(), "REDX_URL="+url, "REDX_KEY="+key)
	outb, err := cmd.CombinedOutput()
	t.Logf("%s", outb)
	if err != nil {
		t.Fatal("C test program failed:", err)
	}
}

func run(t *testing.T, dir, name string, args ...string) {
	t.Helper()
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, b)
	}
}
