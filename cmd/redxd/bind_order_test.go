package main

import (
	"context"
	"io"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// runCaptured runs runDaemon with stdout captured until it returns or ctx ends.
func runCaptured(t *testing.T, ctx context.Context, cfgPath string) (string, error) {
	t.Helper()
	rd, wr, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	old := os.Stdout
	os.Stdout = wr
	captured := make(chan string, 1)
	go func() { b, _ := io.ReadAll(rd); captured <- string(b) }()
	runErr := runDaemon(ctx, []string{"--config", cfgPath}, func(string) {})
	os.Stdout = old
	wr.Close()
	return <-captured, runErr
}

// A taken listen port must fail startup before any first-run admin key exists.
func TestBusyPortCreatesNoBootstrapKey(t *testing.T) {
	dir := t.TempDir()
	busy, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer busy.Close()
	cfgFor := func(addr string) string {
		p := filepath.Join(dir, "redx.toml")
		writeFile(t, p, "data_dir = '"+filepath.ToSlash(dir)+"'\nlisten = '"+addr+"'\nlog_level = 'quiet'\nargon_memory_kib = 64\nargon_time = 1\nbootstrap = 'console'\ntls = 'off'\n")
		return p
	}

	out, err := runCaptured(t, context.Background(), cfgFor(busy.Addr().String()))
	if err == nil || !strings.Contains(err.Error(), "address already in use") {
		t.Fatalf("want bind error, got %v", err)
	}
	if strings.Contains(out, "rx_") || strings.Contains(out, "ADMIN API key") {
		t.Fatalf("busy-port start printed an admin key:\n%s", out)
	}

	// No key may have been persisted: a later start on a free port must still be
	// the first run and print a fresh bootstrap key.
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err = runCaptured(t, ctx, cfgFor(freeAddr(t)))
	if err != nil {
		t.Fatalf("second start: %v", err)
	}
	if !strings.Contains(out, "ADMIN API key") || !strings.Contains(out, "rx_") {
		t.Fatalf("second start found an existing key (orphan persisted); stdout:\n%s", out)
	}
}
