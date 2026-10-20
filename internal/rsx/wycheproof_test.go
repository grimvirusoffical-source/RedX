package rsx

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

type wpFile struct {
	NumberOfTests int `json:"numberOfTests"`
	TestGroups    []struct {
		KeySize   int `json:"keySize"`
		IvSize    int `json:"ivSize"`
		TagSize   int `json:"tagSize"`
		PublicKey struct {
			Pk string `json:"pk"`
		} `json:"publicKey"`
		Tests []struct {
			TcID   int      `json:"tcId"`
			Flags  []string `json:"flags"`
			Key    string   `json:"key"`
			Iv     string   `json:"iv"`
			Aad    string   `json:"aad"`
			Msg    string   `json:"msg"`
			Ct     string   `json:"ct"`
			Tag    string   `json:"tag"`
			Sig    string   `json:"sig"`
			Ikm    string   `json:"ikm"`
			Salt   string   `json:"salt"`
			Info   string   `json:"info"`
			Size   int      `json:"size"`
			Okm    string   `json:"okm"`
			Result string   `json:"result"`
		} `json:"tests"`
	} `json:"testGroups"`
}

func loadWP(t *testing.T, name string) wpFile {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vecDir, "wycheproof", name))
	if err != nil {
		t.Fatal(err)
	}
	var f wpFile
	if err := json.Unmarshal(b, &f); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestWycheproofEd25519(t *testing.T) {
	f := loadWP(t, "ed25519_test.json")
	n := 0
	for _, g := range f.TestGroups {
		pk := unhex(t, g.PublicKey.Pk)
		for _, c := range g.Tests {
			got := Ed25519Verify(pk, unhex(t, c.Msg), unhex(t, c.Sig))
			if got != (c.Result == "valid") {
				t.Errorf("tc %d (%v): got %v want %s", c.TcID, c.Flags, got, c.Result)
			}
			n++
		}
	}
	if n != f.NumberOfTests || n < 100 {
		t.Fatalf("ran %d of %d", n, f.NumberOfTests)
	}
}

func TestWycheproofChaCha20Poly1305(t *testing.T) {
	f := loadWP(t, "chacha20_poly1305_test.json")
	n := 0
	for _, g := range f.TestGroups {
		for _, c := range g.Tests {
			key, iv := unhex(t, c.Key), unhex(t, c.Iv)
			pt, err := AeadDecrypt(key, iv, unhex(t, c.Aad), unhex(t, c.Ct), unhex(t, c.Tag))
			if c.Result == "valid" {
				if err != nil || !CtEq(pt, unhex(t, c.Msg)) {
					t.Errorf("tc %d: valid case failed: %v", c.TcID, err)
				}
				ct, tag, _ := AeadEncrypt(key, iv, unhex(t, c.Aad), unhex(t, c.Msg))
				if !CtEq(ct, unhex(t, c.Ct)) || !CtEq(tag[:], unhex(t, c.Tag)) {
					t.Errorf("tc %d: encrypt mismatch", c.TcID)
				}
			} else if err == nil {
				t.Errorf("tc %d (%v): invalid case accepted", c.TcID, c.Flags)
			}
			n++
		}
	}
	if n != f.NumberOfTests {
		t.Fatalf("ran %d of %d", n, f.NumberOfTests)
	}
}

func TestWycheproofHmacSha1(t *testing.T) {
	f := loadWP(t, "hmac_sha1_test.json")
	n := 0
	for _, g := range f.TestGroups {
		for _, c := range g.Tests {
			m := HmacSha1(unhex(t, c.Key), unhex(t, c.Msg))
			want := unhex(t, c.Tag)
			ok := CtEq(m[:len(want)], want)
			if ok != (c.Result == "valid") {
				t.Errorf("tc %d: got %v want %s", c.TcID, ok, c.Result)
			}
			n++
		}
	}
	if n != f.NumberOfTests {
		t.Fatalf("ran %d of %d", n, f.NumberOfTests)
	}
}

func TestWycheproofHmacSha256(t *testing.T) {
	f := loadWP(t, "hmac_sha256_test.json")
	n := 0
	for _, g := range f.TestGroups {
		for _, c := range g.Tests {
			m := HmacSha256(unhex(t, c.Key), unhex(t, c.Msg))
			want := unhex(t, c.Tag)
			ok := CtEq(m[:len(want)], want)
			if ok != (c.Result == "valid") {
				t.Errorf("tc %d: got %v want %s", c.TcID, ok, c.Result)
			}
			n++
		}
	}
	if n != f.NumberOfTests {
		t.Fatalf("ran %d of %d", n, f.NumberOfTests)
	}
}

func TestWycheproofHkdfSha256(t *testing.T) {
	f := loadWP(t, "hkdf_sha256_test.json")
	n := 0
	for _, g := range f.TestGroups {
		for _, c := range g.Tests {
			o, err := HkdfSha256(unhex(t, c.Ikm), unhex(t, c.Salt), unhex(t, c.Info), c.Size)
			if c.Result == "valid" {
				if err != nil || !CtEq(o, unhex(t, c.Okm)) {
					t.Errorf("tc %d: %v", c.TcID, err)
				}
			} else if err == nil {
				t.Errorf("tc %d: invalid size accepted", c.TcID)
			}
			n++
		}
	}
	if n != f.NumberOfTests {
		t.Fatalf("ran %d of %d", n, f.NumberOfTests)
	}
}

func TestTOTPRFC6238(t *testing.T) {
	key := []byte("12345678901234567890")
	for _, c := range []struct {
		t    int64
		want string
	}{{59, "94287082"}, {1111111109, "07081804"}, {1111111111, "14050471"}, {1234567890, "89005924"}, {2000000000, "69279037"}, {20000000000, "65353130"}} {
		got, err := TOTP(key, c.t, 0, 30, 8)
		if err != nil || got != c.want {
			t.Fatalf("TOTP(%d) = %s, want %s", c.t, got, c.want)
		}
	}
	if !TOTPVerify(key, "94287082", 59+30, 0, 30, 8, 1) || TOTPVerify(key, "94287082", 59+90, 0, 30, 8, 1) {
		t.Fatal("TOTPVerify skew window")
	}
	// RFC 4226 Appendix D (HOTP, 6 digits)
	want := []string{"755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"}
	for i, w := range want {
		if got, _ := HOTP(key, uint64(i), 6); got != w {
			t.Fatalf("HOTP(%d) = %s want %s", i, got, w)
		}
	}
	// RFC 2202 HMAC-SHA1 test case 1 and 6
	k := make([]byte, 20)
	for i := range k {
		k[i] = 0x0b
	}
	m := HmacSha1(k, []byte("Hi There"))
	eqHex(t, "hmac-sha1 rfc2202 tc1", m[:], "b617318655057264e28bc0b6fb378c8ef146be00")
	k = make([]byte, 80)
	for i := range k {
		k[i] = 0xaa
	}
	m = HmacSha1(k, []byte("Test Using Larger Than Block-Size Key - Hash Key First"))
	eqHex(t, "hmac-sha1 rfc2202 tc6", m[:], "aa4ae5e15272d00e95705637ce8a3b55ed402112")
}
