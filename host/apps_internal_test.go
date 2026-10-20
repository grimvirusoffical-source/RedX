package host

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestPodmanSpecSandbox(t *testing.T) {
	spec, err := podmanRunArgs(specInput{
		AppID: "ha_abc", DeployID: "hd_1", Kind: "container", Image: "ghcr.io/acme/app:1",
		HostPort: 20000, EnvFile: "/var/lib/redx/hosted/apps/ha_abc/env",
		Limit: AppLimit{CPU: 0.25, MemoryMB: 256, Pids: 64, DiskMB: 512}, Volume: "/var/lib/redx/hosted/apps/ha_abc/releases/hd_1",
		Canary: true, UID: 200001, User: "rxapp-abc", DiskMB: 512,
	})
	if err != nil {
		t.Fatal(err)
	}
	joined := strings.Join(spec.Args, "\n")
	for _, want := range []string{
		"--userns=keep-id", "--cap-drop=ALL", "--security-opt=no-new-privileges",
		"--security-opt=seccomp=/usr/share/containers/seccomp.json", "--read-only",
		"--network=pasta:--no-map-gw", "-p\n127.0.0.1:20001:8080", "--memory=256m", "--cpus=0.25",
		"--cgroup-parent\nredx-tenant-abc.slice", "--user\n200001:200001",
		"--storage-opt\nsize=512m",
		"--pids-limit=64", "--tmpfs\n/tmp:rw,noexec,nosuid,size=64m",
		"--env-file\n/var/lib/redx/hosted/apps/ha_abc/env",
		"--name\nredxha-abc-canary",
	} {
		if !strings.Contains(joined, want) {
			t.Fatalf("missing %q in\n%s", want, joined)
		}
	}
	for _, bad := range []string{"--network=host", "--privileged", "docker.sock", "--env\n", ":7777", ":7780", "STRIPE"} {
		if strings.Contains(joined, bad) {
			t.Fatalf("spec contains %q", bad)
		}
	}
	if spec.UID != 200001 || spec.Egress != "internet" || len(spec.Deny) == 0 || spec.RunAs[0] != "sudo" {
		t.Fatalf("%+v", spec)
	}
	if !spec.Rootless || spec.Engine != "podman" {
		t.Fatalf("%+v", spec)
	}
}

func TestExtractArchiveRejectsEscape(t *testing.T) {
	dir := t.TempDir()
	err := extractZip(zipSlip(), dir, 1<<20)
	if err == nil {
		t.Fatal("zip slip was accepted")
	}
	if _, statErr := os.Stat(filepath.Join(dir, "..", "pwned.txt")); statErr == nil {
		t.Fatal("zip slip wrote outside the release")
	}
	err = extractTar(tarLink(), dir, 1<<20, false)
	if err == nil || !strings.Contains(err.Error(), "link") {
		t.Fatalf("symlink: %v", err)
	}
}

func zipSlip() []byte {
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	w, err := zw.Create("../pwned.txt")
	if err != nil {
		panic(err)
	}
	_, _ = w.Write([]byte("nope"))
	_ = zw.Close()
	return buf.Bytes()
}

func tarLink() []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	hdr := &tar.Header{Name: "link", Typeflag: tar.TypeSymlink, Linkname: "/etc/passwd", Size: 0, Mode: 0o777}
	if err := tw.WriteHeader(hdr); err != nil {
		panic(err)
	}
	_ = tw.Close()
	return buf.Bytes()
}

func TestPodmanEnvDropsHostSecrets(t *testing.T) {
	t.Setenv("STRIPE_SECRET_KEY", "sk_live_nope")
	t.Setenv("PATH", "/usr/bin")
	joined := strings.Join(podmanEnv(), "\n")
	if strings.Contains(joined, "STRIPE") || strings.Contains(joined, "sk_live") {
		t.Fatal(joined)
	}
	if !strings.Contains(joined, "PATH=/usr/bin") {
		t.Fatal(joined)
	}
}

func TestBuiltinAppLimits(t *testing.T) {
	basic, ok := builtinAppLimit("basic")
	em, ok2 := builtinAppLimit("emerald")
	if !ok || !ok2 || basic.MaxApps != 1 || basic.MemoryMB != 256 || em.MaxApps != 32 || em.MemoryMB != 8192 || em.LogDays != 90 {
		t.Fatalf("basic %+v emerald %+v", basic, em)
	}
	if _, ok := builtinAppLimit("free"); ok {
		t.Fatal("unknown tier")
	}
}
