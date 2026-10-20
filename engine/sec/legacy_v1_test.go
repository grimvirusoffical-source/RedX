package sec

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"testing"
)

// testdata/rxsec_v1.json was written by the pre-migration code (AES-256-GCM, RedX
// d1f2122) and is read here through the Red-SecretsXAI AES-GCM migration reader.
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

func TestLegacyV1ReadRewrapAndReject(t *testing.T) {
	m, mk := loadV1(t)
	ring, _ := NewKeyring(mk)
	ctx := Options{Context: []byte(m["context"])}
	for name, n := range map[string]int{"empty": 0, "small": 100, "multi": 100} {
		ct, _ := hex.DecodeString(m[name])
		if ct[5] != 1 {
			t.Fatalf("%s: fixture is not v1", name)
		}
		pt, err := DecryptBytes(ct, ring, ctx)
		if err != nil || !bytes.Equal(pt, v1pt(n)) {
			t.Fatalf("%s: v1 read: %v", name, err)
		}
		// wrong context, flipped byte in a segment, truncation: all rejected
		if _, err := DecryptBytes(ct, ring, Options{Context: []byte("other")}); !errors.Is(err, ErrAuth) {
			t.Fatalf("%s: wrong context: %v", name, err)
		}
		bad := append([]byte(nil), ct...)
		bad[len(bad)-1] ^= 1
		if _, err := DecryptBytes(bad, ring, ctx); err == nil {
			t.Fatalf("%s: tampered v1 accepted", name)
		}
		if _, err := DecryptBytes(ct[:len(ct)-1], ring, ctx); err == nil {
			t.Fatalf("%s: truncated v1 accepted", name)
		}
		// migration: Rewrap of a v1 file produces v2 under the new key, same plaintext
		k2, _ := RandomKey()
		mk2, _ := NewMasterKey("pack-key-2", k2)
		up, err := RewrapBytes(ct, ring, mk2, ctx)
		if err != nil {
			t.Fatal(err)
		}
		if up[5] != formatVersion {
			t.Fatalf("%s: rewrap wrote version %d", name, up[5])
		}
		ring2, _ := NewKeyring(mk2)
		pt2, err := DecryptBytes(up, ring2, ctx)
		if err != nil || !bytes.Equal(pt2, v1pt(n)) {
			t.Fatalf("%s: migrated read: %v", name, err)
		}
		if _, err := DecryptBytes(up, ring, ctx); err == nil {
			t.Fatalf("%s: old key still opens the migrated file", name)
		}
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
	// relabelling v2 as v1 (downgrade) must fail authentication
	ct[5] = 1
	if _, err := DecryptBytes(ct, ring, Options{Context: []byte("c")}); !errors.Is(err, ErrAuth) {
		t.Fatalf("downgrade relabel: %v", err)
	}
}
