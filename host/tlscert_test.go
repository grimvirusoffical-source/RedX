package host_test

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"redx/host"
	"redx/host/internal/stubstore"
)

// makeCert writes cert.pem/key.pem valid from nb to na and returns their paths.
func makeCert(t *testing.T, dir string, nb, na time.Time) (string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: "redx-test"}, NotBefore: nb, NotAfter: na,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, DNSNames: []string{"localhost"}, IPAddresses: []net.IP{net.ParseIP("127.0.0.1")}}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	c, k := filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if err := os.WriteFile(c, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(k, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		t.Fatal(err)
	}
	return c, k
}

func TestCertStatusStates(t *testing.T) {
	now := time.Now()
	day := 24 * time.Hour
	for _, c := range []struct {
		name         string
		nb, na       time.Time
		state, mustS string
	}{
		{"healthy", now.Add(-day), now.Add(200 * day), "ok", ""},
		{"13 days left", now.Add(-day), now.Add(13*day + time.Hour), "expiring", "expires on"},
		{"15 days left", now.Add(-day), now.Add(15*day + time.Hour), "ok", ""},
		{"expired 30 days ago", now.Add(-400 * day), now.Add(-30 * day), "expired", "EXPIRED"},
		{"not yet valid", now.Add(10 * day), now.Add(300 * day), "not_yet_valid", "NOT VALID YET"},
	} {
		cf, _ := makeCert(t, t.TempDir(), c.nb, c.na)
		ci := host.CertStatus(cf, now)
		if ci.State != c.state || (c.mustS != "" && !strings.Contains(ci.Message, c.mustS)) || (c.state == "ok") != ci.Healthy() {
			t.Errorf("%s: state=%q healthy=%v msg=%q", c.name, ci.State, ci.Healthy(), ci.Message)
		}
	}
	if ci := host.CertStatus(filepath.Join(t.TempDir(), "nope.pem"), now); ci.State != "unreadable" {
		t.Errorf("missing file: %+v", ci)
	}
}

// tls=files with a bad certificate still starts, but logs a clear WARNING at startup and shows it in the admin status.
func TestTLSFilesCertWarnings(t *testing.T) {
	now := time.Now()
	day := 24 * time.Hour
	for _, c := range []struct {
		name   string
		nb, na time.Time
		state  string
		word   string
	}{
		{"expired", now.Add(-400 * day), now.Add(-30 * day), "expired", "EXPIRED"},
		{"expiring", now.Add(-day), now.Add(5 * day), "expiring", "expires on"},
		{"not yet valid", now.Add(3 * day), now.Add(90 * day), "not_yet_valid", "NOT VALID YET"},
	} {
		t.Run(c.name, func(t *testing.T) {
			dir := t.TempDir()
			cert, key := makeCert(t, t.TempDir(), c.nb, c.na)
			cfg := baseCfg(dir)
			cfg.TLS, cfg.TLSCert, cfg.TLSKey = "files", cert, key
			cfg.Listen = "127.0.0.1:0"
			var mu sync.Mutex
			var logs []string
			h, err := host.New(cfg, func(d string, f bool) (host.Backend, error) { return stubstore.Open(d, f) }, func(f string, a ...interface{}) {
				mu.Lock()
				logs = append(logs, strings.TrimSpace(fmt.Sprintf(f, a...)))
				mu.Unlock()
			})
			if err != nil {
				t.Fatal(err)
			}
			ln, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithCancel(context.Background())
			done := make(chan error, 1)
			go func() { done <- h.Serve(ctx, ln) }()
			defer func() { cancel(); <-done }()
			deadline := time.Now().Add(5 * time.Second)
			var warned bool
			for time.Now().Before(deadline) && !warned {
				mu.Lock()
				for _, l := range logs {
					if strings.Contains(l, "WARNING: ") && strings.Contains(l, c.word) {
						warned = true
					}
				}
				mu.Unlock()
				time.Sleep(20 * time.Millisecond)
			}
			if !warned {
				mu.Lock()
				defer mu.Unlock()
				t.Fatalf("no startup warning containing %q; log: %v", c.word, logs)
			}
			// the admin status (shown by the console) carries it too; the handler is reachable in-process
			req := httptest.NewRequest("GET", "/v1/admin/status", nil)
			req.Header.Set("Authorization", "Bearer "+h.BootstrapKey)
			rec := httptest.NewRecorder()
			h.Handler().ServeHTTP(rec, req)
			rr := rec.Body.String()
			var s struct {
				Warn string `json:"tls_warning"`
				Cert struct {
					State string `json:"state"`
				} `json:"tls_cert"`
			}
			if err := json.Unmarshal([]byte(rr), &s); err != nil || s.Cert.State != c.state || !strings.Contains(s.Warn, c.word) {
				t.Fatalf("admin status lacks the warning: %v %s", err, rr)
			}
		})
	}
}
