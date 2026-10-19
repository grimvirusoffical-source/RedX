package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// redxd -h must not print a join link/code or other secret taken from the environment or redx.toml.
func TestRedxdHelpNeverShowsSecrets(t *testing.T) {
	dir := t.TempDir()
	bin := filepath.Join(dir, "redxd")
	if runtime.GOOS == "windows" {
		bin += ".exe"
	}
	if out, err := exec.Command("go", "build", "-o", bin, "redx/cmd/redxd").CombinedOutput(); err != nil {
		t.Fatalf("build: %v %s", err, out)
	}
	data := filepath.Join(dir, "data")
	os.MkdirAll(data, 0o700)
	writeFile(t, filepath.Join(data, "redx.toml"), "join = \"https://127.0.0.1:7777 RX-TOMLS-ECRET\"\ncluster_secret = \"toml-cluster-DUMMY\"\n")
	for _, args := range [][]string{{"run", "-h"}, {"run", "--data-dir", data, "-h"}, {"-h"}, {"service", "-h"}, {"genkey", "-h"}} {
		cmd := exec.Command(bin, args...)
		cmd.Env = append(os.Environ(), "REDX_JOIN=https://127.0.0.1:7777 RX-ENVVV-SECRT", "REDX_CLUSTER_SECRET=env-cluster-DUMMY",
			"REDX_KEYSTORE_PASSPHRASE=env-pass-DUMMY", "REDX_DATA_DIR="+data, "REDX_NO_OPEN=1")
		out, _ := cmd.CombinedOutput()
		for _, s := range []string{"RX-ENVVV-SECRT", "RX-TOMLS-ECRET", "env-cluster-DUMMY", "toml-cluster-DUMMY", "env-pass-DUMMY"} {
			if strings.Contains(string(out), s) {
				t.Fatalf("redxd %v leaks a secret in its help output", args)
			}
		}
	}
}
