package rsx

import "io"

// Reader is a cryptographically secure random source backed by Random, for APIs
// that take an io.Reader.
var Reader io.Reader = randReader{}

type randReader struct{}

func (randReader) Read(p []byte) (int, error) {
	if err := Random(p); err != nil {
		return 0, err
	}
	return len(p), nil
}

// RandomBytes returns n fresh random bytes.
func RandomBytes(n int) ([]byte, error) {
	b := make([]byte, n)
	if err := Random(b); err != nil {
		return nil, err
	}
	return b, nil
}

// NewHMACSHA256 returns a streaming HMAC-SHA256 keyed with key.
func NewHMACSHA256(key []byte) *HMAC { return NewHMAC(newSHA256Hash, key) }

// NewSHA256Hash returns a streaming SHA-256 as the package Hash interface.
func NewSHA256Hash() Hash { return NewSHA256() }
