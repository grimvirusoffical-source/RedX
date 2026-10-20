package host

import (
	"errors"

	"redx/internal/rsx"
)

// Ed25519 (RFC 8032) through Red-SecretsXAI. A private key is seed(32) ||
// public(32), the same layout as before, so existing signing keys and the
// (deterministic) signatures made with them are unchanged.
const (
	edSeedSize       = 32
	edPrivateKeySize = 64
	edSignatureSize  = 64
)

type edPrivateKey []byte

func (k edPrivateKey) Seed() []byte   { return append([]byte(nil), k[:edSeedSize]...) }
func (k edPrivateKey) Public() []byte { return append([]byte(nil), k[edSeedSize:]...) }

// Equal reports whether o is the same private key (constant time).
func (k edPrivateKey) Equal(o []byte) bool { return rsx.CtEq(k, o) }

func edKeyFromSeed(seed []byte) (edPrivateKey, error) {
	if len(seed) != edSeedSize {
		return nil, errors.New("ed25519: seed must be 32 bytes")
	}
	k, err := rsx.Ed25519KeyFromSeed(seed)
	return edPrivateKey(k), err
}

func edGenerateKey() (edPrivateKey, error) {
	_, priv, err := rsx.Ed25519GenerateKey()
	return edPrivateKey(priv), err
}
