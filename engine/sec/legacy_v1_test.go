package sec

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"strings"
	"testing"
)

// testdata/rxsec_v1.json was written by the pre-migration code (AES-256-GCM, RedX
// d1f2122). v1 is no longer supported: these files must be refused before any
// decryption is attempted, with ErrLegacyFormat.
func loadV1(t *testing.T) (map[string]string, *MasterKey) {
	b, err := os.ReadFile("testdata/rxsec_v1.json")
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]string
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatal(err)
	}
	k, _ := hex.DecodeString(m["key"])
	mk, err := NewMasterKey("pack-key-1", k)
	if err != nil {
		t.Fatal(err)
	}
	return m, mk
}

func v1pt(n int) []byte {
	p := make([]byte, n)
	for i := range p {
		p[i] = byte(i*31 + 7)
	}
	return p
}

func TestLegacyV1Refused(t *testing.T) {
	m, mk := loadV1(t)
	ring, _ := NewKeyring(mk)
	ctx := Options{Context: []byte(m["context"])}
	for _, name := range []string{"empty", "small", "multi"} {
		ct, _ := hex.DecodeString(m[name])
		if ct[5] != 1 {
			t.Fatalf("%s: fixture is not v1", name)
		}
		if _, err := DecryptBytes(ct, ring, ctx); !errors.Is(err, ErrLegacyFormat) || !errors.Is(err, ErrFormat) {
			t.Fatalf("%s: v1 decrypt: %v", name, err)
		}
		if _, err := NewReader(bytes.NewReader(ct), ring, ctx); !errors.Is(err, ErrLegacyFormat) {
			t.Fatalf("%s: v1 reader: %v", name, err)
		}
		k2, _ := RandomKey()
		mk2, _ := NewMasterKey("pack-key-2", k2)
		if _, err := RewrapBytes(ct, ring, mk2, ctx); !errors.Is(err, ErrLegacyFormat) {
			t.Fatalf("%s: v1 rewrap: %v", name, err)
		}
		if _, err := KeyID(bytes.NewReader(ct)); !errors.Is(err, ErrLegacyFormat) {
			t.Fatalf("%s: key id: %v", name, err)
		}
	}
	if !strings.Contains(ErrLegacyFormat.Error(), "recreate it with this version") {
		t.Fatal(ErrLegacyFormat)
	}
}

func TestNewWritesAreV2AndVersionIsAuthenticated(t *testing.T) {
	_, mk := loadV1(t)
	ring, _ := NewKeyring(mk)
	ct, err := EncryptBytes(v1pt(100), mk, Options{Context: []byte("c"), SegmentSize: 16})
	if err != nil {
		t.Fatal(err)
	}
	if ct[5] != 2 {
		t.Fatalf("new write is version %d", ct[5])
	}
	pt, err := DecryptBytes(ct, ring, Options{Context: []byte("c")})
	if err != nil || !bytes.Equal(pt, v1pt(100)) {
		t.Fatal("v2 round trip", err)
	}
	// relabelling v2 as v1 is refused as legacy; any other version is a format error
	ct[5] = 1
	if _, err := DecryptBytes(ct, ring, Options{Context: []byte("c")}); !errors.Is(err, ErrLegacyFormat) {
		t.Fatalf("downgrade relabel: %v", err)
	}
	ct[5] = 3
	if _, err := DecryptBytes(ct, ring, Options{Context: []byte("c")}); !errors.Is(err, ErrFormat) || errors.Is(err, ErrLegacyFormat) {
		t.Fatalf("version 3: %v", err)
	}
}
