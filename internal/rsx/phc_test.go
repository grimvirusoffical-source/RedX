package rsx

import (
	"strings"
	"testing"
)

// Reference vectors from the Argon2 reference implementation's test suite (argon2id, v=19,
// t=2, m=2^16, p=1, salt "somesalt"); the raw hashes were re-derived independently with
// OpenSSL's ARGON2ID KDF and match.
var phcVectors = []struct{ pw, phc, rawHex string }{
	{"password", "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$CTFhFdXPJO1aFaMaO6Mm5c8y7cJHAph8ArZWb2GRPPc",
		"09316115d5cf24ed5a15a31a3ba326e5cf32edc24702987c02b6566f61913cf7"},
	{"differentpassword", "$argon2id$v=19$m=65536,t=2,p=1$c29tZXNhbHQ$C4TWUs9rDEvq7w3+J4umqA32aWKB1+DSiRuBfYxFj94",
		"0b84d652cf6b0c4beaef0dfe278ba6a80df6696281d7e0d2891b817d8c458fde"},
}

func TestPHCReferenceVectors(t *testing.T) {
	for _, v := range phcVectors {
		p, err := ParsePHC(v.phc)
		if err != nil {
			t.Fatal(err)
		}
		if p.M != 65536 || p.T != 2 || p.P != 1 || string(p.Salt) != "somesalt" {
			t.Fatalf("parsed %+v", p)
		}
		eqHex(t, "phc hash", p.Hash, v.rawHex)
		h, err := Argon2id([]byte(v.pw), p.Salt, p.T, p.M, p.P, 32)
		if err != nil {
			t.Fatal(err)
		}
		eqHex(t, "argon2id "+v.pw, h, v.rawHex)
		enc, _ := p.Encode()
		if enc != v.phc {
			t.Fatalf("re-encode %s", enc)
		}
		if ok, err := VerifyPasswordPHC([]byte(v.pw), v.phc); !ok || err != nil {
			t.Fatal("verify")
		}
		if ok, _ := VerifyPasswordPHC([]byte(v.pw+"x"), v.phc); ok {
			t.Fatal("wrong password verified")
		}
	}
}

func TestPHCStrictParsing(t *testing.T) {
	good := phcVectors[0].phc
	bad := []string{
		strings.Replace(good, "argon2id", "argon2i", 1),
		strings.Replace(good, "v=19", "v=16", 1),
		strings.Replace(good, "$v=19", "", 1),
		strings.Replace(good, "m=65536,t=2,p=1", "t=2,m=65536,p=1", 1),
		strings.Replace(good, "m=65536", "m=065536", 1),
		strings.Replace(good, "p=1", "p=1,keyid=AAAA", 1),
		strings.Replace(good, "t=2", "t=0", 1),
		strings.Replace(good, "t=2", "t=99", 1),
		strings.Replace(good, "m=65536", "m=4294967295", 1),
		strings.Replace(good, "m=65536", "m=99999999999", 1),
		strings.Replace(good, "c29tZXNhbHQ", "c29tZXNhbHQ=", 1),
		strings.Replace(good, "c29tZXNhbHQ", "c2", 1),
		strings.Replace(good, "c29tZXNhbHQ", "c29t*XNhbHQ", 1),
		good + "$",
		good[:len(good)-30],
		"",
		"$argon2id",
	}
	for _, s := range bad {
		if _, err := ParsePHC(s); err == nil {
			t.Errorf("accepted %q", s)
		}
	}
}

func TestPHCRoundTrip(t *testing.T) {
	s, err := HashPasswordPHC([]byte("hunter22hunter22"), 1, 64, 1)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(s, "$argon2id$v=19$m=64,t=1,p=1$") {
		t.Fatal(s)
	}
	if ok, _ := VerifyPasswordPHC([]byte("hunter22hunter22"), s); !ok {
		t.Fatal("verify")
	}
}
