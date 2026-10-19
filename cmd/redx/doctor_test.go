package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"redx/host"
	"redx/host/engineadapter"
)

// `redx doctor` must check the running daemon's data directory (asked via --key), not this
// machine's default directory.
func TestDoctorUsesRunningDaemonDataDir(t *testing.T) {
	t.Setenv("REDX_DATA_DIR", "") // not set: doctor may ask the daemon
	cfg := host.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.ArgonMemKiB, cfg.ArgonTime = 64, 1
	cfg.LogLevel = "quiet"
	h, err := host.New(cfg, engineadapter.Opener(engineadapter.Config{SweepMS: 50}), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.Handler())
	t.Cleanup(func() { srv.Close(); h.Close() })

	out, _, _ := runCLI(t, srv.URL, h.BootstrapKey, "doctor")
	if !strings.Contains(out, cfg.DataDir) || !strings.Contains(out, "running daemon's directory") {
		t.Fatalf("doctor did not use the daemon's data dir %s:\n%s", cfg.DataDir, out)
	}
	if strings.Contains(out, "does not exist yet") {
		t.Fatalf("doctor warned about a data dir that does not exist:\n%s", out)
	}
	// without a key it must not claim the default dir is missing while a daemon answers
	out, _, _ = runCLI(t, srv.URL, "", "doctor")
	if strings.Contains(out, "does not exist yet") || !strings.Contains(out, "data directory is unknown") {
		t.Fatalf("keyless doctor output wrong:\n%s", out)
	}
}

// doctor loads <data dir>/redx.toml and flags an expired, soon-to-expire or not-yet-valid tls=files certificate.
func TestDoctorFlagsBadTLSFilesCertificate(t *testing.T) {
	t.Setenv("REDX_DATA_DIR", "")
	day := 24 * time.Hour
	now := time.Now()
	for _, c := range []struct {
		name   string
		nb, na time.Time
		status string
		word   string
	}{
		{"expired", now.Add(-400 * day), now.Add(-30 * day), "FAIL", "EXPIRED"},
		{"expiring", now.Add(-day), now.Add(5 * day), "warn", "expires on"},
		{"not yet valid", now.Add(3 * day), now.Add(90 * day), "FAIL", "NOT VALID YET"},
		{"healthy", now.Add(-day), now.Add(100 * day), "ok", "expires"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"}, NotBefore: c.nb, NotAfter: c.na}
			der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
			cert := filepath.Join(dir, "c.pem")
			os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
			os.WriteFile(filepath.Join(dir, "redx.toml"), []byte("tls = \"files\"\ntls_cert = "+strconv.Quote(cert)+"\ntls_key = "+strconv.Quote(cert)+"\n"), 0o600)
			out, _, _ := runCLI(t, "http://127.0.0.1:1", "", "doctor", "--data-dir", dir)
			if !strings.Contains(out, "loaded "+filepath.Join(dir, "redx.toml")) {
				t.Errorf("doctor did not load redx.toml from the --data-dir:\n%s", out)
			}
			line := ""
			for _, l := range strings.Split(out, "\n") {
				if strings.Contains(l, "tls cert") {
					line = l
				}
			}
			if !strings.Contains(line, c.status) || !strings.Contains(line, c.word) {
				t.Errorf("tls cert line = %q, want status %s and %q\n%s", line, c.status, c.word, out)
			}
		})
	}
}

func writeTestCert(t *testing.T, dir string, nb, na time.Time) string {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "t"}, NotBefore: nb, NotAfter: na}
	der, _ := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	cert := filepath.Join(dir, "c.pem")
	os.WriteFile(cert, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	kb, _ := x509.MarshalECPrivateKey(key)
	os.WriteFile(filepath.Join(dir, "k.pem"), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return cert
}

func tlsCertLine(out string) string {
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "tls cert") && !strings.Contains(l, "served") {
			return l
		}
	}
	return ""
}

// the cert check ran only inside "data dir exists"; with --config before the first start, or with
// the cert given as redxd flags, an expired certificate went unreported.
func TestDoctorChecksCertWithoutDataDirAndFromFlags(t *testing.T) {
	t.Setenv("REDX_DATA_DIR", "")
	now := time.Now()
	dir := t.TempDir()
	cert := writeTestCert(t, dir, now.Add(-400*24*time.Hour), now.Add(-30*24*time.Hour))
	missing := filepath.Join(dir, "not-created-yet")
	cfgf := filepath.Join(dir, "redxd.toml")
	os.WriteFile(cfgf, []byte("tls = \"files\"\ntls_cert = "+strconv.Quote(cert)+"\ntls_key = "+strconv.Quote(filepath.Join(dir, "k.pem"))+"\n"), 0o600)
	out, _, _ := runCLI(t, "http://127.0.0.1:1", "", "doctor", "--data-dir", missing, "--config", cfgf)
	if l := tlsCertLine(out); !strings.Contains(l, "FAIL") || !strings.Contains(l, "EXPIRED") {
		t.Fatalf("--config before the data dir exists: tls cert line %q\n%s", l, out)
	}
	out, _, _ = runCLI(t, "http://127.0.0.1:1", "", "doctor", "--data-dir", missing, "--tls", "files", "--tls-cert", cert)
	if l := tlsCertLine(out); !strings.Contains(l, "FAIL") || !strings.Contains(l, "EXPIRED") {
		t.Fatalf("cert as flags: tls cert line %q\n%s", l, out)
	}
	t.Setenv("REDX_TLS", "files")
	t.Setenv("REDX_TLS_CERT", cert)
	t.Setenv("REDX_TLS_KEY", filepath.Join(dir, "k.pem"))
	out, _, _ = runCLI(t, "http://127.0.0.1:1", "", "doctor", "--data-dir", missing)
	if l := tlsCertLine(out); !strings.Contains(l, "FAIL") {
		t.Fatalf("cert from env: tls cert line %q\n%s", l, out)
	}
}

// With --key, doctor reports the certificate the running daemon really serves (set by a redxd flag doctor never saw).
func TestDoctorReportsDaemonServedCert(t *testing.T) {
	t.Setenv("REDX_DATA_DIR", "")
	now := time.Now()
	dir := t.TempDir()
	cert := writeTestCert(t, dir, now.Add(-24*time.Hour), now.Add(5*24*time.Hour))
	cfg := host.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.ArgonMemKiB, cfg.ArgonTime = 64, 1
	cfg.LogLevel = "quiet"
	cfg.TLS, cfg.TLSCert, cfg.TLSKey = "files", cert, filepath.Join(dir, "k.pem")
	h, err := host.New(cfg, engineadapter.Opener(engineadapter.Config{SweepMS: 50}), t.Logf)
	if err != nil {
		t.Fatal(err)
	}
	tc, _, err := h.TLSConfig() // records the served certificate, as Serve does
	if err != nil || tc == nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(h.Handler())
	t.Cleanup(func() { srv.Close(); h.Close() })
	out, _, _ := runCLI(t, srv.URL, h.BootstrapKey, "doctor")
	if !strings.Contains(out, "served tls cert") || !strings.Contains(out, "expires on") {
		t.Fatalf("doctor should report the daemon's expiring certificate:\n%s", out)
	}
}

// A valid certificate given as flags must not fail "config valid" for the key doctor was not given;
// with --tls-key the pair is checked.
func TestDoctorCertFlagsWithoutAndWithKey(t *testing.T) {
	t.Setenv("REDX_DATA_DIR", "")
	now := time.Now()
	dir := t.TempDir()
	cert := writeTestCert(t, dir, now.Add(-24*time.Hour), now.Add(200*24*time.Hour))
	missing := filepath.Join(dir, "not-created-yet")
	out, _, _ := runCLI(t, "http://127.0.0.1:1", "", "doctor", "--offline", "--data-dir", missing, "--tls", "files", "--tls-cert", cert)
	if strings.Contains(out, "config valid") || !strings.Contains(out, "--tls-key") {
		t.Fatalf("cert-only flags must not fail the config check:\n%s", out)
	}
	if l := tlsCertLine(out); !strings.Contains(l, "ok") {
		t.Fatalf("valid cert should be ok: %q\n%s", l, out)
	}
	out, _, _ = runCLI(t, "http://127.0.0.1:1", "", "doctor", "--offline", "--data-dir", missing, "--tls-cert", cert, "--tls-key", filepath.Join(dir, "k.pem"))
	if !strings.Contains(out, "matches the certificate") || strings.Contains(out, "config valid") {
		t.Fatalf("cert + key flags:\n%s", out)
	}
	other := t.TempDir()
	writeTestCert(t, other, now.Add(-24*time.Hour), now.Add(200*24*time.Hour))
	out, _, _ = runCLI(t, "http://127.0.0.1:1", "", "doctor", "--offline", "--data-dir", missing, "--tls-cert", cert, "--tls-key", filepath.Join(other, "k.pem"))
	if !strings.Contains(out, "do not load as a pair") {
		t.Fatalf("mismatched key must be reported:\n%s", out)
	}
}
