package rsx

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// vecDir is the repository's shared vectors/ directory (the same files the C++ and other SDKs use).
var vecDir = filepath.Join("testdata", "vectors")

func unhex(t testing.TB, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex %q: %v", s, err)
	}
	return b
}

func loadVec(t testing.TB, name string, v interface{}) {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(vecDir, name))
	if err != nil {
		t.Fatalf("vectors: %v", err)
	}
	if err := json.Unmarshal(b, v); err != nil {
		t.Fatalf("vectors %s: %v", name, err)
	}
}

func eqHex(t *testing.T, what string, got []byte, want string) {
	t.Helper()
	if hex.EncodeToString(got) != want {
		t.Fatalf("%s:\n got  %x\n want %s", what, got, want)
	}
}

func TestSha256Vectors(t *testing.T) {
	var f struct {
		Vectors []struct {
			Name, Msg string
			MsgHex    string `json:"msg_hex"`
			Hash      string
		}
	}
	loadVec(t, "sha256.json", &f)
	if len(f.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range f.Vectors {
		m := []byte(v.Msg)
		if v.MsgHex != "" {
			m = unhex(t, v.MsgHex)
		}
		h := Sha256(m)
		eqHex(t, "sha256 "+v.Name, h[:], v.Hash)
	}
	// FIPS 180-4 two-block message and the one-million-'a' message
	h := Sha256([]byte("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
	eqHex(t, "sha256 448-bit", h[:], "248d6a61d20638b8e5c026930c3e6039a33ce45964ff2167f6ecedd419db06c1")
	s := NewSHA256()
	a := make([]byte, 1000)
	for i := range a {
		a[i] = 'a'
	}
	for i := 0; i < 1000; i++ {
		s.Write(a)
	}
	eqHex(t, "sha256 million a", s.Sum(nil), "cdc76e5c9914fb9281a1c7e284d73e67f1809a48a497200e046d39ccc7112cd0")
}

func TestSha512Vectors(t *testing.T) {
	h := Sha512([]byte("abc"))
	eqHex(t, "sha512 abc", h[:], "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f")
	h = Sha512(nil)
	eqHex(t, "sha512 empty", h[:], "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e")
	h = Sha512([]byte("abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"))
	eqHex(t, "sha512 896-bit", h[:], "8e959b75dae313da8cf4f72814fc143f8f7779c6eb9f7fa17299aeadb6889018501d289e4900f7e4331b99dec4b5433ac7d329eeb6dd26545e96e55b874be909")
}

func TestSha1Vectors(t *testing.T) {
	s := NewSHA1()
	s.Write([]byte("abc"))
	eqHex(t, "sha1 abc", s.Sum(nil), "a9993e364706816aba3e25717850c26c9cd0d89d")
	s.Reset()
	s.Write([]byte("abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"))
	eqHex(t, "sha1 448-bit", s.Sum(nil), "84983e441c3bd26ebaae4aa1f95129e5e54670f1")
	s.Reset()
	eqHex(t, "sha1 empty", s.Sum(nil), "da39a3ee5e6b4b0d3255bfef95601890afd80709")
}

func TestHmacSha256Vectors(t *testing.T) {
	var f struct {
		Vectors []struct{ Name, KeyHex, MsgHex, Mac string }
	}
	b, _ := os.ReadFile(filepath.Join(vecDir, "hmac_sha256.json"))
	var raw struct {
		Vectors []map[string]string
	}
	json.Unmarshal(b, &raw)
	_ = f
	if len(raw.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range raw.Vectors {
		m := HmacSha256(unhex(t, v["key_hex"]), unhex(t, v["msg_hex"]))
		eqHex(t, "hmac "+v["name"], m[:], v["mac"])
	}
	// RFC 4231 test case 6: key longer than the block size
	k := make([]byte, 131)
	for i := range k {
		k[i] = 0xaa
	}
	m := HmacSha256(k, []byte("Test Using Larger Than Block-Size Key - Hash Key First"))
	eqHex(t, "hmac rfc4231 tc6", m[:], "60e431591ee0b67f0d8a26aacbf5b77f8e0bc6213728c5140546040f0ee37f54")
}

func TestHkdfVectors(t *testing.T) {
	var raw struct {
		Vectors []struct {
			Name, Ikm, Salt, Info, Okm string
			L                          int
		}
	}
	loadVec(t, "hkdf_sha256.json", &raw)
	for _, v := range raw.Vectors {
		o, err := HkdfSha256(unhex(t, v.Ikm), unhex(t, v.Salt), unhex(t, v.Info), v.L)
		if err != nil {
			t.Fatal(err)
		}
		eqHex(t, "hkdf "+v.Name, o, v.Okm)
	}
	// RFC 5869 A.2 (long inputs)
	ikm, salt, info := make([]byte, 80), make([]byte, 80), make([]byte, 80)
	for i := 0; i < 80; i++ {
		ikm[i], salt[i], info[i] = byte(i), byte(0x60+i), byte(0xb0+i)
	}
	o, _ := HkdfSha256(ikm, salt, info, 82)
	eqHex(t, "hkdf A.2", o, "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87")
	if _, err := HkdfSha256(ikm, nil, nil, 255*32+1); err != ErrParam {
		t.Fatal("hkdf over-length must be refused")
	}
}

func TestPbkdf2Vectors(t *testing.T) {
	for _, c := range []struct {
		it   uint32
		want string
	}{{1, "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"},
		{2, "ae4d0c95af6b46d32d0adff928f06dd02a303f8ef3c251dfd6e2d85a95474c43"},
		{4096, "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"}} {
		o, _ := Pbkdf2Sha256([]byte("password"), []byte("salt"), c.it, 32)
		eqHex(t, "pbkdf2", o, c.want)
	}
	// RFC 7914 §11 (PBKDF2-HMAC-SHA256, c=1, dkLen=64)
	o, _ := Pbkdf2Sha256([]byte("passwd"), []byte("salt"), 1, 64)
	eqHex(t, "pbkdf2 rfc7914", o, "55ac046e56e3089fec1691c22544b605f94185216dde0465e68b9d57c20dacbc49ca9cccf179b645991664b39d77ef317c71b845b1e30bd509112041d3a19783")
}

func TestBlake2bVectors(t *testing.T) {
	o, _ := Blake2b([]byte("abc"), nil, 64)
	eqHex(t, "blake2b abc", o, "ba80a53f981c4d0d6a2797b69f12f6e94c212f14685ac4b74b12bb6fdbffa2d17d87c5392aab792dc252d5de4533cc9518d38aa8dbf1925ab92386edd4009923")
	o, _ = Blake2b(nil, nil, 64)
	eqHex(t, "blake2b empty", o, "786a02f742015903c6c6fd852552d272912f4740e15847618a86e217f71f5419d25e1031afee585313896444934eb04b903a685b1448b755d56f701afe9be2ce")
	// Keyed KAT from the BLAKE2 reference (blake2b-kat.txt): key 00..3f, in = "" and in = 00
	key := make([]byte, 64)
	for i := range key {
		key[i] = byte(i)
	}
	o, _ = Blake2b(nil, key, 64)
	eqHex(t, "blake2b keyed kat[0]", o, "10ebb67700b1868efb4417987acf4690ae9d972fb7a590c2f02871799aaa4786b5e996e8f0f4eb981fc214b005f42d2ff4233499391653df7aefcbc13fc51568")
	o, _ = Blake2b([]byte{0}, key, 64)
	eqHex(t, "blake2b keyed kat[1]", o, "961f6dd1e4dd30f63901690c512e78e4b45e4742ed197c3c5e45c549fd25f2e4187b0bc9fe30492b16b0d0bc4ef9b0f34c7003fac09a5ef1532e69430234cebd")
	if _, err := Blake2b(nil, nil, 65); err != ErrParam {
		t.Fatal("outLen 65 must be refused")
	}
}

func TestChaChaVectors(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	nonce := unhex(t, "000000000000004a00000000")
	pt := []byte("Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.")
	ct := make([]byte, len(pt))
	ChaCha20(key, nonce, 1, pt, ct)
	eqHex(t, "chacha20 2.4.2", ct, "6e2e359a2568f98041ba0728dd0d6981e97e7aec1d4360c20a27afccfd9fae0bf91b65c5524733ab8f593dabcd62b3571639d624e65152ab8f530c359f0861d807ca0dbf500d6a6156a38e088a22b65e52bc514d16ccf806818ce91ab77937365af90bbf74a35be6b40b8eedf2785e42874d")

	var f struct {
		Vectors []struct {
			Name, Key, Nonce, Aad, Ciphertext, Tag string
			PlaintextASCII                         string `json:"plaintext_ascii"`
		}
	}
	loadVec(t, "chacha20_poly1305.json", &f)
	for _, v := range f.Vectors {
		c, tag, _ := AeadEncrypt(unhex(t, v.Key), unhex(t, v.Nonce), unhex(t, v.Aad), []byte(v.PlaintextASCII))
		eqHex(t, "aead ct "+v.Name, c, v.Ciphertext)
		eqHex(t, "aead tag "+v.Name, tag[:], v.Tag)
		p, err := AeadDecrypt(unhex(t, v.Key), unhex(t, v.Nonce), unhex(t, v.Aad), c, tag[:])
		if err != nil || string(p) != v.PlaintextASCII {
			t.Fatal("aead decrypt")
		}
		tag[0] ^= 1
		if _, err := AeadDecrypt(unhex(t, v.Key), unhex(t, v.Nonce), unhex(t, v.Aad), c, tag[:]); err != ErrAuth {
			t.Fatal("aead bad tag must be ErrAuth")
		}
	}
	// RFC 8439 §2.5.2 Poly1305
	pk := unhex(t, "85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
	tg, _ := Poly1305(pk, []byte("Cryptographic Forum Research Group"))
	eqHex(t, "poly1305 2.5.2", tg[:], "a8061dc1305136c6c22b8baf0c0127a9")
	// RFC 8439 A.3 #11/#12 edge cases (h wraps past 2^130-5)
	tg, _ = Poly1305(unhex(t, "0200000000000000000000000000000000000000000000000000000000000000"), unhex(t, "ffffffffffffffffffffffffffffffff"))
	eqHex(t, "poly1305 A.3 #5", tg[:], "03000000000000000000000000000000")
	tg, _ = Poly1305(unhex(t, "02000000000000000000000000000000ffffffffffffffffffffffffffffffff"), unhex(t, "02000000000000000000000000000000"))
	eqHex(t, "poly1305 A.3 #6", tg[:], "03000000000000000000000000000000")
	tg, _ = Poly1305(unhex(t, "0100000000000000000000000000000000000000000000000000000000000000"), unhex(t, "fffffffffffffffffffffffffffffffff0ffffffffffffffffffffffffffffff11000000000000000000000000000000"))
	eqHex(t, "poly1305 A.3 #7", tg[:], "05000000000000000000000000000000")
	tg, _ = Poly1305(unhex(t, "0100000000000000000000000000000000000000000000000000000000000000"), unhex(t, "fffffffffffffffffffffffffffffffffbfefefefefefefefefefefefefefefe01010101010101010101010101010101"))
	eqHex(t, "poly1305 A.3 #8", tg[:], "00000000000000000000000000000000")
	tg, _ = Poly1305(unhex(t, "0200000000000000000000000000000000000000000000000000000000000000"), unhex(t, "fdffffffffffffffffffffffffffffff"))
	eqHex(t, "poly1305 A.3 #9", tg[:], "faffffffffffffffffffffffffffffff")
}

func TestArgon2idVectors(t *testing.T) {
	var f struct {
		Vectors []struct {
			Name        string
			PasswordHex string `json:"password_hex"`
			SaltHex     string `json:"salt_hex"`
			SecretHex   string `json:"secret_hex"`
			AdHex       string `json:"ad_hex"`
			T           uint32
			MKiB        uint32 `json:"m_kib"`
			P           uint32
			Tag         string
		}
	}
	loadVec(t, "argon2id.json", &f)
	if len(f.Vectors) == 0 {
		t.Fatal("no vectors")
	}
	for _, v := range f.Vectors {
		o, err := Argon2idExt(unhex(t, v.PasswordHex), unhex(t, v.SaltHex), unhex(t, v.SecretHex), unhex(t, v.AdHex), v.T, v.MKiB, v.P, len(v.Tag)/2)
		if err != nil {
			t.Fatal(err)
		}
		eqHex(t, "argon2id "+v.Name, o, v.Tag)
	}
	if _, err := Argon2id([]byte("p"), []byte("somesalt"), 1, Argon2MMax+1, 1, 32); err != ErrRange {
		t.Fatal("m over max must be ErrRange")
	}
	if _, err := Argon2id([]byte("p"), []byte("somesalt"), Argon2TMax+1, 32, 1, 32); err != ErrRange {
		t.Fatal("t over max must be ErrRange")
	}
}

func TestCtEqAndRandom(t *testing.T) {
	if !CtEq([]byte("abc"), []byte("abc")) || CtEq([]byte("abc"), []byte("abd")) || CtEq([]byte("ab"), []byte("abc")) {
		t.Fatal("CtEq")
	}
	a, b := make([]byte, 64), make([]byte, 64)
	if Random(a) != nil || Random(b) != nil || CtEq(a, b) || CtEq(a, make([]byte, 64)) {
		t.Fatal("Random must give distinct non-zero output")
	}
	Wipe(a)
	if !CtEq(a, make([]byte, 64)) {
		t.Fatal("Wipe")
	}
}
