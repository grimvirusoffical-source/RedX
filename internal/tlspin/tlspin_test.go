package tlspin_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"redx/internal/tlspin"
)

func TestPinHandshake(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok")) }))
	defer srv.Close()
	der := srv.Certificate().Raw
	ref := sha256.Sum256(der) // independent oracle (test only)
	fp := hex.EncodeToString(ref[:])
	if tlspin.Fingerprint(der) != fp {
		t.Fatal("fingerprint differs from the reference SHA-256")
	}
	colon := strings.ToUpper(fp[:2]) + ":" + fp[2:]
	for _, pin := range []string{fp, "sha256:" + fp, colon} {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: tlspin.Config(pin)}}
		r, err := c.Get(srv.URL)
		if err != nil {
			t.Fatalf("pin %q: %v", pin, err)
		}
		r.Body.Close()
	}
	other := []byte(fp)
	if other[0] == 'a' {
		other[0] = 'b'
	} else {
		other[0] = 'a'
	}
	for _, pin := range []string{string(other), "", "zz", fp[:62]} {
		c := &http.Client{Transport: &http.Transport{TLSClientConfig: tlspin.Config(pin)}}
		if r, err := c.Get(srv.URL); err == nil {
			r.Body.Close()
			t.Fatalf("pin %q accepted", pin)
		}
	}
	if _, err := tlspin.Parse("sha256:" + fp[:63] + "g"); err == nil {
		t.Fatal("bad hex accepted")
	}
}

// The SDK module carries an identical copy (it cannot import the main module).
func TestSDKCopyIdentical(t *testing.T) {
	a, err1 := os.ReadFile("tlspin.go")
	b, err2 := os.ReadFile("../../sdk/go/internal/tlspin/tlspin.go")
	if err1 != nil || err2 != nil {
		t.Fatal(err1, err2)
	}
	b = bytes.Replace(b, []byte(`"github.com/grimvirusoffical-source/RedX/sdk/go/internal/rsx"`), []byte(`"redx/internal/rsx"`), 1)
	if !bytes.Equal(a, b) {
		t.Fatal("sdk/go/internal/tlspin/tlspin.go differs from internal/tlspin/tlspin.go")
	}
}
