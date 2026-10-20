package rsx

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestVendoredCopiesMatch checks that both vendored copies (this package, which the tests
// exercise, and sdk/go/internal/rsx, which the public Go SDK builds) are byte-identical
// and match the per-file SHA-256 list in VENDOR.txt.
func TestVendoredCopiesMatch(t *testing.T) {
	f, err := os.Open("VENDOR.txt")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	n := 0
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		fs := strings.Fields(sc.Text())
		if len(fs) != 2 || len(fs[0]) != 64 || !strings.HasSuffix(fs[1], ".go") {
			continue
		}
		a, err := os.ReadFile(fs[1])
		if err != nil {
			t.Fatal(err)
		}
		b, err := os.ReadFile(filepath.Join("..", "..", "sdk", "go", "internal", "rsx", fs[1]))
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(a, b) {
			t.Errorf("%s differs between internal/rsx and sdk/go/internal/rsx", fs[1])
		}
		h := Sha256(a)
		if hexs(h[:]) != fs[0] {
			t.Errorf("%s does not match VENDOR.txt", fs[1])
		}
		n++
	}
	if n < 20 {
		t.Fatalf("VENDOR.txt lists only %d files", n)
	}
}

func hexs(b []byte) string {
	const d = "0123456789abcdef"
	o := make([]byte, 2*len(b))
	for i, c := range b {
		o[2*i], o[2*i+1] = d[c>>4], d[c&15]
	}
	return string(o)
}
