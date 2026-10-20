package host

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"redx/internal/rsx"
	"redx/internal/tlspin"
	"time"
)

// Fingerprint returns the lowercase hex SHA-256 of the leaf certificate in a PEM file.
func Fingerprint(certFile string) (string, error) {
	b, err := os.ReadFile(certFile)
	if err != nil {
		return "", err
	}
	blk, _ := pem.Decode(b)
	if blk == nil {
		return "", fmt.Errorf("no PEM block in %s", certFile)
	}
	return tlspin.Fingerprint(blk.Bytes), nil
}

// EnsureSelfSigned creates (or reuses, if still valid >30 days) an ECDSA P-256
// self-signed certificate under dir. Returns cert/key paths.
func EnsureSelfSigned(dir string, extraHosts []string) (certFile, keyFile string, err error) {
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return
	}
	certFile, keyFile = filepath.Join(dir, "cert.pem"), filepath.Join(dir, "key.pem")
	if b, e := os.ReadFile(certFile); e == nil {
		if blk, _ := pem.Decode(b); blk != nil {
			if c, e := x509.ParseCertificate(blk.Bytes); e == nil && time.Until(c.NotAfter) > 30*24*time.Hour {
				if _, e := os.Stat(keyFile); e == nil {
					return
				}
			}
		}
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rsx.Reader)
	if err != nil {
		return
	}
	sb, err := rsx.RandomBytes(15) // 120-bit serial
	if err != nil {
		return
	}
	serial := new(big.Int).SetBytes(sb)
	tpl := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "redxd self-signed", Organization: []string{"RedX"}},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(825 * 24 * time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	hosts := append([]string{"localhost", "127.0.0.1", "::1"}, extraHosts...)
	if hn, e := os.Hostname(); e == nil {
		hosts = append(hosts, hn)
	}
	for _, h := range hosts {
		if ip := net.ParseIP(h); ip != nil {
			tpl.IPAddresses = append(tpl.IPAddresses, ip)
		} else {
			tpl.DNSNames = append(tpl.DNSNames, h)
		}
	}
	der, err := x509.CreateCertificate(rsx.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	if err = os.WriteFile(certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		return
	}
	err = os.WriteFile(keyFile, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600)
	return
}

// TLSConfig builds the server TLS config for cfg (nil when TLS is off).
func (h *Host) TLSConfig() (*tls.Config, string, error) {
	var cert, key string
	switch h.Cfg.TLS {
	case "auto":
		var err error
		cert, key, err = EnsureSelfSigned(filepath.Join(h.Cfg.DataDir, "tls"), h.Cfg.TLSHosts)
		if err != nil {
			return nil, "", err
		}
	case "files":
		cert, key = h.Cfg.TLSCert, h.Cfg.TLSKey
	default:
		return nil, "", nil
	}
	kp, err := tls.LoadX509KeyPair(cert, key)
	if err != nil {
		return nil, "", err
	}
	fp, _ := Fingerprint(cert)
	h.runMu.Lock()
	h.tlsCertFile = cert
	h.runMu.Unlock()
	return &tls.Config{Certificates: []tls.Certificate{kp}, MinVersion: tls.VersionTLS12}, fp, nil
}

// CertWarnDays is how close to expiry a certificate must be before it is flagged.
const CertWarnDays = 14

// CertInfo describes the validity of the certificate the host serves.
type CertInfo struct {
	NotBefore time.Time `json:"not_before"`
	NotAfter  time.Time `json:"not_after"`
	DaysLeft  int       `json:"days_left"`
	State     string    `json:"state"`   // ok | expiring | expired | not_yet_valid | unreadable
	Message   string    `json:"message"` // empty when state is ok
}

// Healthy reports whether the certificate needs no attention.
func (c CertInfo) Healthy() bool { return c.State == "ok" }

// CertStatus reads the first certificate in certFile and judges it at time now: expired, not valid yet, or
// expiring within CertWarnDays days all produce a clear message.
func CertStatus(certFile string, now time.Time) CertInfo {
	b, err := os.ReadFile(certFile)
	if err != nil {
		return CertInfo{State: "unreadable", Message: "cannot read the TLS certificate: " + err.Error()}
	}
	for {
		var blk *pem.Block
		blk, b = pem.Decode(b)
		if blk == nil {
			return CertInfo{State: "unreadable", Message: "no certificate found in " + certFile}
		}
		if blk.Type != "CERTIFICATE" {
			continue
		}
		c, err := x509.ParseCertificate(blk.Bytes)
		if err != nil {
			return CertInfo{State: "unreadable", Message: "cannot parse the TLS certificate: " + err.Error()}
		}
		return judgeCert(c.NotBefore, c.NotAfter, now)
	}
}

func judgeCert(nb, na, now time.Time) CertInfo {
	ci := CertInfo{NotBefore: nb, NotAfter: na, DaysLeft: int(na.Sub(now).Hours() / 24), State: "ok"}
	switch {
	case now.Before(nb):
		ci.State = "not_yet_valid"
		ci.Message = fmt.Sprintf("TLS certificate is NOT VALID YET (valid from %s): clients will refuse it. Check this computer's clock or replace tls_cert/tls_key.", nb.UTC().Format("2006-01-02 15:04 MST"))
	case !now.Before(na):
		ci.State = "expired"
		ci.DaysLeft = -int(now.Sub(na).Hours() / 24)
		ci.Message = fmt.Sprintf("TLS certificate EXPIRED on %s (%d days ago): browsers and clients will refuse it. Replace tls_cert/tls_key and restart.", na.UTC().Format("2006-01-02"), -ci.DaysLeft)
	case na.Sub(now) < CertWarnDays*24*time.Hour:
		ci.State = "expiring"
		ci.Message = fmt.Sprintf("TLS certificate expires on %s (in %d days): renew it before then and restart.", na.UTC().Format("2006-01-02"), ci.DaysLeft)
	}
	return ci
}
