package redx_test

import (
	"bufio"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"sync"
	"testing"
	"time"
)

// host is a real redxd on a free port with a throwaway data dir. The bootstrap admin key is read from its
// output and never printed.
type host struct {
	URL, AdminKey string
	bin, data     string
	port          int
	cmd           *exec.Cmd
	t             *testing.T
}

var (
	buildOnce sync.Once
	builtBin  string
	buildErr  error
)

func redxdBin(t *testing.T) string {
	if b := os.Getenv("REDXD_BIN"); b != "" {
		return b
	}
	buildOnce.Do(func() {
		dir, err := os.MkdirTemp("", "redx-go-sdk-")
		if err != nil {
			buildErr = err
			return
		}
		builtBin = filepath.Join(dir, "redxd")
		if runtime.GOOS == "windows" {
			builtBin += ".exe"
		}
		cmd := exec.Command("go", "build", "-o", builtBin, "./cmd/redxd")
		cmd.Dir = filepath.Join("..", "..", "..")
		cmd.Stdout, cmd.Stderr = os.Stderr, os.Stderr
		buildErr = cmd.Run()
	})
	if buildErr != nil {
		t.Fatal("building redxd:", buildErr)
	}
	return builtBin
}

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

var keyRe = regexp.MustCompile(`rx_live_[A-Za-z0-9]{43}`)

func startHost(t *testing.T) *host {
	t.Helper()
	h := &host{bin: redxdBin(t), data: filepath.Join(t.TempDir(), "data"), port: freePort(t), t: t}
	h.URL = "http://127.0.0.1:" + strconv.Itoa(h.port)
	h.spawn()
	t.Cleanup(h.kill)
	return h
}

func (h *host) spawn() {
	h.t.Helper()
	cmd := exec.Command(h.bin, "run", "--no-open", "--bootstrap", "console", "--data-dir", h.data, "--listen", "127.0.0.1:"+strconv.Itoa(h.port))
	cmd.Env = []string{"PATH=" + os.Getenv("PATH"), "HOME=" + h.t.TempDir(), "SYSTEMROOT=" + os.Getenv("SYSTEMROOT")}
	out, _ := cmd.StdoutPipe()
	cmd.Stderr = io.Discard
	if err := cmd.Start(); err != nil {
		h.t.Fatal(err)
	}
	h.cmd = cmd
	keyCh := make(chan string, 1)
	go func() {
		sc := bufio.NewScanner(out)
		sent := false
		for sc.Scan() {
			if m := keyRe.FindString(sc.Text()); m != "" && !sent {
				keyCh <- m
				sent = true
			}
		}
	}()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case k := <-keyCh:
			if h.AdminKey == "" {
				h.AdminKey = k
			}
		default:
		}
		if res, err := http.Get(h.URL + "/healthz"); err == nil {
			res.Body.Close()
			if res.StatusCode == 200 && h.AdminKey != "" {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	h.t.Fatal("redxd did not become ready")
}

func (h *host) kill() {
	if h.cmd != nil && h.cmd.Process != nil {
		_ = h.cmd.Process.Kill()
		_, _ = h.cmd.Process.Wait()
	}
}

// restart kills the host and starts it again on the same port and data (to test reconnects).
func (h *host) restart(down time.Duration) {
	h.kill()
	time.Sleep(down)
	h.spawn()
}
