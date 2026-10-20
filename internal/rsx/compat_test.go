package rsx

import (
	"bytes"
	"io"
	"testing"
)

func TestCompatHelpers(t *testing.T) {
	a := make([]byte, 100000)
	if _, err := io.ReadFull(Reader, a); err != nil {
		t.Fatal(err)
	}
	b, _ := RandomBytes(100000)
	if bytes.Equal(a, b) || bytes.Equal(a, make([]byte, len(a))) {
		t.Fatal("random")
	}
	// RFC 4231 test case 2 through the streaming API
	m := NewHMACSHA256([]byte("Jefe"))
	m.Write([]byte("what do ya want "))
	m.Write([]byte("for nothing?"))
	eqHex(t, "hmac stream", m.Sum(nil), "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
}
