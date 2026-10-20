package rsx

import "math/bits"

// Hash is the streaming interface shared by the hashes in this package.
type Hash interface {
	Write(p []byte) (int, error)
	Sum(b []byte) []byte // appends the digest; does not change the state
	Reset()
	Size() int
	BlockSize() int
}

// ---------- SHA-256 (FIPS 180-4) ----------

var k256 = [64]uint32{
	0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
	0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
	0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
	0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
	0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
	0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
	0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
	0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2}

// SHA256 is a streaming SHA-256.
type SHA256 struct {
	h   [8]uint32
	buf [64]byte
	n   int
	len uint64
}

func NewSHA256() *SHA256         { s := &SHA256{}; s.Reset(); return s }
func (s *SHA256) Size() int      { return 32 }
func (s *SHA256) BlockSize() int { return 64 }
func (s *SHA256) Reset() {
	s.h = [8]uint32{0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19}
	s.n, s.len = 0, 0
}
func (s *SHA256) block(p []byte) {
	var w [64]uint32
	for i := 0; i < 16; i++ {
		w[i] = rd32(p[4*i:])
	}
	for i := 16; i < 64; i++ {
		s0 := bits.RotateLeft32(w[i-15], -7) ^ bits.RotateLeft32(w[i-15], -18) ^ (w[i-15] >> 3)
		s1 := bits.RotateLeft32(w[i-2], -17) ^ bits.RotateLeft32(w[i-2], -19) ^ (w[i-2] >> 10)
		w[i] = w[i-16] + s0 + w[i-7] + s1
	}
	a, b, c, d, e, f, g, h := s.h[0], s.h[1], s.h[2], s.h[3], s.h[4], s.h[5], s.h[6], s.h[7]
	for i := 0; i < 64; i++ {
		S1 := bits.RotateLeft32(e, -6) ^ bits.RotateLeft32(e, -11) ^ bits.RotateLeft32(e, -25)
		t1 := h + S1 + ((e & f) ^ (^e & g)) + k256[i] + w[i]
		S0 := bits.RotateLeft32(a, -2) ^ bits.RotateLeft32(a, -13) ^ bits.RotateLeft32(a, -22)
		t2 := S0 + ((a & b) ^ (a & c) ^ (b & c))
		h, g, f, e, d, c, b, a = g, f, e, d+t1, c, b, a, t1+t2
	}
	s.h[0] += a
	s.h[1] += b
	s.h[2] += c
	s.h[3] += d
	s.h[4] += e
	s.h[5] += f
	s.h[6] += g
	s.h[7] += h
	wipe32(w[:])
}
func (s *SHA256) Write(p []byte) (int, error) {
	n := len(p)
	s.len += uint64(n)
	for len(p) > 0 {
		k := copy(s.buf[s.n:], p)
		s.n += k
		p = p[k:]
		if s.n == 64 {
			s.block(s.buf[:])
			s.n = 0
		}
	}
	return n, nil
}
func (s *SHA256) Sum(b []byte) []byte {
	c := *s
	var pad [72]byte
	pad[0] = 0x80
	padLen := 56 - c.n
	if c.n >= 56 {
		padLen = 120 - c.n
	}
	be64(pad[padLen:], c.len*8)
	c.Write(pad[:padLen+8])
	var out [32]byte
	for i := 0; i < 8; i++ {
		be32(out[4*i:], c.h[i])
	}
	Wipe(c.buf[:])
	return append(b, out[:]...)
}

// Sha256 returns SHA-256(msg).
func Sha256(msg []byte) [32]byte {
	s := NewSHA256()
	s.Write(msg)
	var o [32]byte
	copy(o[:], s.Sum(nil))
	return o
}

// ---------- SHA-512 (FIPS 180-4) ----------

var k512 = [80]uint64{
	0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc, 0x3956c25bf348b538,
	0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118, 0xd807aa98a3030242, 0x12835b0145706fbe,
	0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2, 0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235,
	0xc19bf174cf692694, 0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
	0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5, 0x983e5152ee66dfab,
	0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4, 0xc6e00bf33da88fc2, 0xd5a79147930aa725,
	0x06ca6351e003826f, 0x142929670a0e6e70, 0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed,
	0x53380d139d95b3df, 0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
	0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30, 0xd192e819d6ef5218,
	0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8, 0x19a4c116b8d2d0c8, 0x1e376c085141ab53,
	0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8, 0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373,
	0x682e6ff3d6b2b8a3, 0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
	0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b, 0xca273eceea26619c,
	0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178, 0x06f067aa72176fba, 0x0a637dc5a2c898a6,
	0x113f9804bef90dae, 0x1b710b35131c471b, 0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc,
	0x431d67c49c100d4c, 0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817}

// SHA512 is a streaming SHA-512.
type SHA512 struct {
	h   [8]uint64
	buf [128]byte
	n   int
	len uint64
}

func NewSHA512() *SHA512         { s := &SHA512{}; s.Reset(); return s }
func (s *SHA512) Size() int      { return 64 }
func (s *SHA512) BlockSize() int { return 128 }
func (s *SHA512) Reset() {
	s.h = [8]uint64{0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
		0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179}
	s.n, s.len = 0, 0
}
func (s *SHA512) block(p []byte) {
	var w [80]uint64
	for i := 0; i < 16; i++ {
		w[i] = rd64(p[8*i:])
	}
	for i := 16; i < 80; i++ {
		s0 := bits.RotateLeft64(w[i-15], -1) ^ bits.RotateLeft64(w[i-15], -8) ^ (w[i-15] >> 7)
		s1 := bits.RotateLeft64(w[i-2], -19) ^ bits.RotateLeft64(w[i-2], -61) ^ (w[i-2] >> 6)
		w[i] = w[i-16] + s0 + w[i-7] + s1
	}
	a, b, c, d, e, f, g, h := s.h[0], s.h[1], s.h[2], s.h[3], s.h[4], s.h[5], s.h[6], s.h[7]
	for i := 0; i < 80; i++ {
		S1 := bits.RotateLeft64(e, -14) ^ bits.RotateLeft64(e, -18) ^ bits.RotateLeft64(e, -41)
		t1 := h + S1 + ((e & f) ^ (^e & g)) + k512[i] + w[i]
		S0 := bits.RotateLeft64(a, -28) ^ bits.RotateLeft64(a, -34) ^ bits.RotateLeft64(a, -39)
		t2 := S0 + ((a & b) ^ (a & c) ^ (b & c))
		h, g, f, e, d, c, b, a = g, f, e, d+t1, c, b, a, t1+t2
	}
	s.h[0] += a
	s.h[1] += b
	s.h[2] += c
	s.h[3] += d
	s.h[4] += e
	s.h[5] += f
	s.h[6] += g
	s.h[7] += h
	wipe64(w[:])
}
func (s *SHA512) Write(p []byte) (int, error) {
	n := len(p)
	s.len += uint64(n)
	for len(p) > 0 {
		k := copy(s.buf[s.n:], p)
		s.n += k
		p = p[k:]
		if s.n == 128 {
			s.block(s.buf[:])
			s.n = 0
		}
	}
	return n, nil
}
func (s *SHA512) Sum(b []byte) []byte {
	c := *s
	var pad [144]byte
	pad[0] = 0x80
	padLen := 112 - c.n
	if c.n >= 112 {
		padLen = 240 - c.n
	}
	// 128-bit length; messages here are < 2^61 bytes so the high word is 0.
	be64(pad[padLen+8:], c.len*8)
	c.Write(pad[:padLen+16])
	var out [64]byte
	for i := 0; i < 8; i++ {
		be64(out[8*i:], c.h[i])
	}
	Wipe(c.buf[:])
	return append(b, out[:]...)
}

// Sha512 returns SHA-512(msg).
func Sha512(msg []byte) [64]byte {
	s := NewSHA512()
	s.Write(msg)
	var o [64]byte
	copy(o[:], s.Sum(nil))
	return o
}

// ---------- SHA-1 (FIPS 180-4). Only for HMAC-SHA1 (TOTP, RFC 6238). ----------

// SHA1 is a streaming SHA-1. Do not use it for anything except HMAC-SHA1/TOTP.
type SHA1 struct {
	h   [5]uint32
	buf [64]byte
	n   int
	len uint64
}

func NewSHA1() *SHA1           { s := &SHA1{}; s.Reset(); return s }
func (s *SHA1) Size() int      { return 20 }
func (s *SHA1) BlockSize() int { return 64 }
func (s *SHA1) Reset() {
	s.h = [5]uint32{0x67452301, 0xEFCDAB89, 0x98BADCFE, 0x10325476, 0xC3D2E1F0}
	s.n, s.len = 0, 0
}
func (s *SHA1) block(p []byte) {
	var w [80]uint32
	for i := 0; i < 16; i++ {
		w[i] = rd32(p[4*i:])
	}
	for i := 16; i < 80; i++ {
		w[i] = bits.RotateLeft32(w[i-3]^w[i-8]^w[i-14]^w[i-16], 1)
	}
	a, b, c, d, e := s.h[0], s.h[1], s.h[2], s.h[3], s.h[4]
	for i := 0; i < 80; i++ {
		var f, k uint32
		switch {
		case i < 20:
			f, k = (b&c)|(^b&d), 0x5A827999
		case i < 40:
			f, k = b^c^d, 0x6ED9EBA1
		case i < 60:
			f, k = (b&c)|(b&d)|(c&d), 0x8F1BBCDC
		default:
			f, k = b^c^d, 0xCA62C1D6
		}
		t := bits.RotateLeft32(a, 5) + f + e + k + w[i]
		e, d, c, b, a = d, c, bits.RotateLeft32(b, 30), a, t
	}
	s.h[0] += a
	s.h[1] += b
	s.h[2] += c
	s.h[3] += d
	s.h[4] += e
	wipe32(w[:])
}
func (s *SHA1) Write(p []byte) (int, error) {
	n := len(p)
	s.len += uint64(n)
	for len(p) > 0 {
		k := copy(s.buf[s.n:], p)
		s.n += k
		p = p[k:]
		if s.n == 64 {
			s.block(s.buf[:])
			s.n = 0
		}
	}
	return n, nil
}
func (s *SHA1) Sum(b []byte) []byte {
	c := *s
	var pad [72]byte
	pad[0] = 0x80
	padLen := 56 - c.n
	if c.n >= 56 {
		padLen = 120 - c.n
	}
	be64(pad[padLen:], c.len*8)
	c.Write(pad[:padLen+8])
	var out [20]byte
	for i := 0; i < 5; i++ {
		be32(out[4*i:], c.h[i])
	}
	return append(b, out[:]...)
}

// ---------- BLAKE2b (RFC 7693) ----------

var b2iv = [8]uint64{0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179}

var b2sigma = [12][16]byte{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4}, {7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13}, {2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11}, {13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5}, {10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15}, {14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3}}

// BLAKE2b is a streaming (optionally keyed) BLAKE2b.
type BLAKE2b struct {
	h      [8]uint64
	t0, t1 uint64
	buf    [128]byte
	n      int
	outLen int
	key    [128]byte
	keyLen int
}

// NewBLAKE2b returns a BLAKE2b with an outLen-byte digest (1..64) and an optional key (<=64 bytes).
func NewBLAKE2b(outLen int, key []byte) (*BLAKE2b, error) {
	if outLen < 1 || outLen > 64 || len(key) > 64 {
		return nil, ErrParam
	}
	b := &BLAKE2b{outLen: outLen, keyLen: len(key)}
	copy(b.key[:], key)
	b.Reset()
	return b, nil
}
func (b *BLAKE2b) Size() int      { return b.outLen }
func (b *BLAKE2b) BlockSize() int { return 128 }
func (b *BLAKE2b) Reset() {
	b.h = b2iv
	b.h[0] ^= 0x01010000 ^ uint64(b.keyLen)<<8 ^ uint64(b.outLen)
	b.t0, b.t1, b.n = 0, 0, 0
	if b.keyLen > 0 {
		copy(b.buf[:], b.key[:])
		b.n = 128
	}
}
func (b *BLAKE2b) compress(block []byte, last bool) {
	var m, v [16]uint64
	for i := 0; i < 16; i++ {
		m[i] = le64(block[8*i:])
	}
	copy(v[:8], b.h[:])
	copy(v[8:], b2iv[:])
	v[12] ^= b.t0
	v[13] ^= b.t1
	if last {
		v[14] = ^v[14]
	}
	g := func(a, bb, c, d int, x, y uint64) {
		v[a] += v[bb] + x
		v[d] = bits.RotateLeft64(v[d]^v[a], -32)
		v[c] += v[d]
		v[bb] = bits.RotateLeft64(v[bb]^v[c], -24)
		v[a] += v[bb] + y
		v[d] = bits.RotateLeft64(v[d]^v[a], -16)
		v[c] += v[d]
		v[bb] = bits.RotateLeft64(v[bb]^v[c], -63)
	}
	for r := 0; r < 12; r++ {
		s := &b2sigma[r]
		g(0, 4, 8, 12, m[s[0]], m[s[1]])
		g(1, 5, 9, 13, m[s[2]], m[s[3]])
		g(2, 6, 10, 14, m[s[4]], m[s[5]])
		g(3, 7, 11, 15, m[s[6]], m[s[7]])
		g(0, 5, 10, 15, m[s[8]], m[s[9]])
		g(1, 6, 11, 12, m[s[10]], m[s[11]])
		g(2, 7, 8, 13, m[s[12]], m[s[13]])
		g(3, 4, 9, 14, m[s[14]], m[s[15]])
	}
	for i := 0; i < 8; i++ {
		b.h[i] ^= v[i] ^ v[i+8]
	}
	wipe64(m[:])
	wipe64(v[:])
}
func (b *BLAKE2b) inc(n uint64) {
	b.t0 += n
	if b.t0 < n {
		b.t1++
	}
}
func (b *BLAKE2b) Write(p []byte) (int, error) {
	n := len(p)
	for len(p) > 0 {
		if b.n == 128 { // only compress when more data follows (the last block is special)
			b.inc(128)
			b.compress(b.buf[:], false)
			b.n = 0
		}
		k := copy(b.buf[b.n:], p)
		b.n += k
		p = p[k:]
	}
	return n, nil
}
func (b *BLAKE2b) Sum(out []byte) []byte {
	c := *b
	c.inc(uint64(c.n))
	for i := c.n; i < 128; i++ {
		c.buf[i] = 0
	}
	c.compress(c.buf[:], true)
	var o [64]byte
	for i := 0; i < 8; i++ {
		putLe64(o[8*i:], c.h[i])
	}
	Wipe(c.buf[:])
	Wipe(c.key[:])
	return append(out, o[:c.outLen]...)
}

// Blake2b returns BLAKE2b-outLen(msg) with an optional key, like rsx_blake2b.
func Blake2b(msg, key []byte, outLen int) ([]byte, error) {
	h, err := NewBLAKE2b(outLen, key)
	if err != nil {
		return nil, err
	}
	h.Write(msg)
	return h.Sum(nil), nil
}

// blake2bLong is H' from RFC 9106 §3.3.
func blake2bLong(out []byte, in ...[]byte) {
	var pref [4]byte
	putLe32(pref[:], uint32(len(out)))
	if len(out) <= 64 {
		h, _ := NewBLAKE2b(len(out), nil)
		h.Write(pref[:])
		for _, p := range in {
			h.Write(p)
		}
		h.Sum(out[:0])
		return
	}
	h, _ := NewBLAKE2b(64, nil)
	h.Write(pref[:])
	for _, p := range in {
		h.Write(p)
	}
	v := h.Sum(nil)
	copy(out, v[:32])
	done := 32
	for len(out)-done > 64 {
		h, _ = NewBLAKE2b(64, nil)
		h.Write(v)
		v = h.Sum(v[:0])
		copy(out[done:], v[:32])
		done += 32
	}
	h, _ = NewBLAKE2b(len(out)-done, nil)
	h.Write(v)
	h.Sum(out[done:done])
	Wipe(v)
}
