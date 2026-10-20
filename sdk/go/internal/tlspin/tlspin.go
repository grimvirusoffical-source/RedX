// Package tlspin pins TLS certificates by the SHA-256 of the leaf certificate
// (DER), computed with Red-SecretsXAI (rsx.Sha256) and compared in constant time.
// It is used wherever RedX controls both ends: the cluster node channel, the redx
// CLI and the Go SDK. Browsers keep normal CA verification.
//
// This file is kept identical in redx/internal/tlspin and
// sdk/go/internal/tlspin (checked by a test in the main module).
package tlspin

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"strings"

	rsx "github.com/grimvirusoffical-source/RedX/sdk/go/internal/rsx"
)

// ErrMismatch is returned by the handshake when the peer certificate is not the pinned one.
var ErrMismatch = errors.New("tls: peer certificate does not match the pinned SHA-256 fingerprint")

// ErrBadPin: the pin is not a SHA-256 in hex.
var ErrBadPin = errors.New("tls: pin must be a SHA-256 in hex (64 hex digits; an optional \"sha256:\" prefix and colons are allowed)")

// Fingerprint is the lowercase hex SHA-256 of a DER certificate.
func Fingerprint(der []byte) string {
	s := rsx.Sha256(der)
	return hex.EncodeToString(s[:])
}

// Parse accepts "sha256:AB:CD..." / "abcd..." forms and returns the 32-byte digest.
func Parse(pin string) ([]byte, error) {
	p := strings.ReplaceAll(strings.TrimPrefix(strings.ToLower(strings.TrimSpace(pin)), "sha256:"), ":", "")
	b, err := hex.DecodeString(p)
	if err != nil || len(b) != 32 {
		return nil, ErrBadPin
	}
	return b, nil
}

// Matches reports whether der is the pinned certificate.
func Matches(der []byte, pin []byte) bool {
	s := rsx.Sha256(der)
	return len(pin) == 32 && rsx.CtEq(s[:], pin)
}

// Config trusts exactly the certificate whose SHA-256 is pin; chain and name
// verification are replaced by the pin. An unparsable pin fails every handshake.
func Config(pin string) *tls.Config {
	want, perr := Parse(pin)
	return &tls.Config{
		InsecureSkipVerify: true, // replaced by VerifyPeerCertificate below
		MinVersion:         tls.VersionTLS12,
		VerifyPeerCertificate: func(raw [][]byte, _ [][]*x509.Certificate) error {
			if perr != nil {
				return perr
			}
			if len(raw) == 0 {
				return errors.New("tls: no peer certificate")
			}
			if !Matches(raw[0], want) {
				return ErrMismatch
			}
			return nil
		},
	}
}
