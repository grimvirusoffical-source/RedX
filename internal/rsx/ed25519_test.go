package rsx

import "testing"

// RFC 8032 §7.1 test vectors (TEST 1, 2, 3, 1024 and SHA(abc)).
var ed25519RFC = []struct{ sk, pk, msg, sig string }{
	{"9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60", "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a", "",
		"e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b"},
	{"4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb", "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c", "72",
		"92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00"},
	{"c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7", "fc51cd8e6218a1a38da47ed00230f0580816ed13ba3303ac5deb911548908025", "af82",
		"6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a"},
	{"833fe62409237b9d62ec77587520911e9a759cec1d19755b7da901b96dca3d42", "ec172b93ad5e563bf4932c70e1245034c35467ef2efd4d64ebf819683467e2bf",
		"ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f",
		"dc2a4459e7369633a52b1bf277839a00201009a3efbf3ecb69bea2186c26b58909351fc9ac90b3ecfdfbc7c66431e0303dca179c138ac17ad9bef1177331a704"},
}

func TestEd25519RFC8032(t *testing.T) {
	for i, v := range ed25519RFC {
		priv, err := Ed25519KeyFromSeed(unhex(t, v.sk))
		if err != nil {
			t.Fatal(err)
		}
		eqHex(t, "pk", priv[32:], v.pk)
		sig, _ := Ed25519Sign(priv, unhex(t, v.msg))
		eqHex(t, "sig", sig, v.sig)
		if !Ed25519Verify(unhex(t, v.pk), unhex(t, v.msg), sig) {
			t.Fatalf("vector %d: verify", i)
		}
		bad := append([]byte(nil), sig...)
		bad[0] ^= 1
		if Ed25519Verify(unhex(t, v.pk), unhex(t, v.msg), bad) {
			t.Fatalf("vector %d: forged R accepted", i)
		}
		bad = append([]byte(nil), sig...)
		bad[40] ^= 1
		if Ed25519Verify(unhex(t, v.pk), unhex(t, v.msg), bad) {
			t.Fatalf("vector %d: forged S accepted", i)
		}
		if Ed25519Verify(unhex(t, v.pk), append(unhex(t, v.msg), 0), sig) {
			t.Fatalf("vector %d: other message accepted", i)
		}
	}
}

func TestEd25519Malleability(t *testing.T) {
	// S + L must be rejected (RFC 8032 §5.1.7 requires 0 <= S < L).
	v := ed25519RFC[0]
	sig := unhex(t, v.sig)
	var s [4]uint64
	for i := 0; i < 4; i++ {
		s[i] = le64(sig[32+8*i:])
	}
	var c uint64
	for i := 0; i < 4; i++ {
		var ci uint64
		s[i], ci = addc(s[i], scL[i], c)
		c = ci
	}
	for i := 0; i < 4; i++ {
		putLe64(sig[32+8*i:], s[i])
	}
	if Ed25519Verify(unhex(t, v.pk), nil, sig) {
		t.Fatal("S+L accepted")
	}
	// non-canonical public key encoding (y = p) must be rejected
	pk := unhex(t, "edffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff7f")
	if Ed25519Verify(pk, nil, unhex(t, v.sig)) {
		t.Fatal("non-canonical A accepted")
	}
}

func addc(a, b, c uint64) (uint64, uint64) {
	s := a + b
	c1 := uint64(0)
	if s < a {
		c1 = 1
	}
	s2 := s + c
	if s2 < s {
		c1 = 1
	}
	return s2, c1
}

func TestEd25519RoundTrip(t *testing.T) {
	pub, priv, err := Ed25519GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte("redx update manifest")
	sig, _ := Ed25519Sign(priv, msg)
	if !Ed25519Verify(pub, msg, sig) {
		t.Fatal("roundtrip")
	}
}
