package rsx

import "math/bits"

func chachaBlock(key *[32]byte, counter uint32, nonce []byte, out *[64]byte) {
	s := [16]uint32{0x61707865, 0x3320646e, 0x79622d32, 0x6b206574,
		le32(key[0:]), le32(key[4:]), le32(key[8:]), le32(key[12:]),
		le32(key[16:]), le32(key[20:]), le32(key[24:]), le32(key[28:]),
		counter, le32(nonce[0:]), le32(nonce[4:]), le32(nonce[8:])}
	x := s
	qr := func(a, b, c, d int) {
		x[a] += x[b]
		x[d] = bits.RotateLeft32(x[d]^x[a], 16)
		x[c] += x[d]
		x[b] = bits.RotateLeft32(x[b]^x[c], 12)
		x[a] += x[b]
		x[d] = bits.RotateLeft32(x[d]^x[a], 8)
		x[c] += x[d]
		x[b] = bits.RotateLeft32(x[b]^x[c], 7)
	}
	for i := 0; i < 10; i++ {
		qr(0, 4, 8, 12)
		qr(1, 5, 9, 13)
		qr(2, 6, 10, 14)
		qr(3, 7, 11, 15)
		qr(0, 5, 10, 15)
		qr(1, 6, 11, 12)
		qr(2, 7, 8, 13)
		qr(3, 4, 9, 14)
	}
	for i := 0; i < 16; i++ {
		putLe32(out[4*i:], x[i]+s[i])
	}
	wipe32(x[:])
	wipe32(s[:])
}

// ChaCha20 XORs in with the RFC 8439 keystream (32-byte key, 12-byte nonce) into out.
func ChaCha20(key, nonce []byte, counter uint32, in, out []byte) error {
	if len(key) != 32 || len(nonce) != 12 || len(out) < len(in) {
		return ErrParam
	}
	var k [32]byte
	copy(k[:], key)
	var blk [64]byte
	for off := 0; off < len(in); off += 64 {
		chachaBlock(&k, counter+uint32(off/64), nonce, &blk)
		n := len(in) - off
		if n > 64 {
			n = 64
		}
		for i := 0; i < n; i++ {
			out[off+i] = in[off+i] ^ blk[i]
		}
	}
	Wipe(blk[:])
	Wipe(k[:])
	return nil
}

// ---- Poly1305 (RFC 8439 §2.5), 130-bit arithmetic in 3x64-bit limbs ----

type poly1305 struct {
	r0, r1     uint64
	h0, h1, h2 uint64
	s0, s1     uint64
	buf        [16]byte
	n          int
}

func newPoly1305(key []byte) *poly1305 {
	p := &poly1305{}
	p.r0 = le64(key[0:]) & 0x0ffffffc0fffffff
	p.r1 = le64(key[8:]) & 0x0ffffffc0ffffffc
	p.s0 = le64(key[16:])
	p.s1 = le64(key[24:])
	return p
}

func (p *poly1305) blocks(m []byte, hibit uint64) {
	h0, h1, h2 := p.h0, p.h1, p.h2
	r0, r1 := p.r0, p.r1
	for len(m) >= 16 {
		var c uint64
		h0, c = bits.Add64(h0, le64(m[0:]), 0)
		h1, c = bits.Add64(h1, le64(m[8:]), c)
		h2 += c + hibit
		// h * r (h2 is small: < 8)
		h0r0hi, h0r0lo := bits.Mul64(h0, r0)
		h1r0hi, h1r0lo := bits.Mul64(h1, r0)
		h0r1hi, h0r1lo := bits.Mul64(h0, r1)
		h1r1hi, h1r1lo := bits.Mul64(h1, r1)
		h2r0 := h2 * r0
		h2r1 := h2 * r1
		// m0 = h0r0lo
		m0 := h0r0lo
		m1, c1 := bits.Add64(h0r0hi, h1r0lo, 0)
		m1, c2 := bits.Add64(m1, h0r1lo, 0)
		m2, c3 := bits.Add64(h1r0hi, h0r1hi, c1)
		m2, c4 := bits.Add64(m2, h1r1lo, c2)
		m2, c5 := bits.Add64(m2, h2r0, 0)
		m3 := h1r1hi + h2r1 + c3 + c4 + c5
		// reduce: value = m0 + m1*2^64 + m2*2^128 + m3*2^192 mod 2^130-5
		h0, h1, h2 = m0, m1, m2&3
		// high part (m2>>2 | m3<<62, m3>>2) times 5 = (hi*4 + hi)
		cc0 := m2 &^ 3
		cc1 := m3
		h0, c = bits.Add64(h0, cc0, 0)
		h1, c = bits.Add64(h1, cc1, c)
		h2 += c
		cc0 = cc0>>2 | cc1<<62
		cc1 = cc1 >> 2
		h0, c = bits.Add64(h0, cc0, 0)
		h1, c = bits.Add64(h1, cc1, c)
		h2 += c
		m = m[16:]
	}
	p.h0, p.h1, p.h2 = h0, h1, h2
}

func (p *poly1305) Write(m []byte) {
	if p.n > 0 {
		k := copy(p.buf[p.n:], m)
		p.n += k
		m = m[k:]
		if p.n < 16 {
			return
		}
		p.blocks(p.buf[:], 1)
		p.n = 0
	}
	if full := len(m) &^ 15; full > 0 {
		p.blocks(m[:full], 1)
		m = m[full:]
	}
	if len(m) > 0 {
		p.n = copy(p.buf[:], m)
	}
}

func (p *poly1305) Sum(tag *[16]byte) {
	if p.n > 0 {
		p.buf[p.n] = 1
		for i := p.n + 1; i < 16; i++ {
			p.buf[i] = 0
		}
		p.blocks(p.buf[:], 0)
	}
	h0, h1, h2 := p.h0, p.h1, p.h2
	// compute h - (2^130 - 5) and select in constant time
	t0, b := bits.Sub64(h0, 0xfffffffffffffffb, 0)
	t1, b := bits.Sub64(h1, 0xffffffffffffffff, b)
	_, b = bits.Sub64(h2, 3, b)
	mask := b - 1 // b==0 (h >= p) -> all ones -> take t
	h0 = (h0 &^ mask) | (t0 & mask)
	h1 = (h1 &^ mask) | (t1 & mask)
	var c uint64
	h0, c = bits.Add64(h0, p.s0, 0)
	h1, _ = bits.Add64(h1, p.s1, c)
	putLe64(tag[0:], h0)
	putLe64(tag[8:], h1)
	*p = poly1305{}
}

// Poly1305 returns the one-time authenticator of msg under the 32-byte key.
func Poly1305(key, msg []byte) ([16]byte, error) {
	var t [16]byte
	if len(key) != 32 {
		return t, ErrParam
	}
	p := newPoly1305(key)
	p.Write(msg)
	p.Sum(&t)
	return t, nil
}

func aeadTag(key *[32]byte, nonce, aad, ct []byte) [16]byte {
	var otk [64]byte
	chachaBlock(key, 0, nonce, &otk)
	p := newPoly1305(otk[:32])
	Wipe(otk[:])
	var z [16]byte
	p.Write(aad)
	if r := len(aad) % 16; r != 0 {
		p.Write(z[:16-r])
	}
	p.Write(ct)
	if r := len(ct) % 16; r != 0 {
		p.Write(z[:16-r])
	}
	var lens [16]byte
	putLe64(lens[0:], uint64(len(aad)))
	putLe64(lens[8:], uint64(len(ct)))
	p.Write(lens[:])
	var tag [16]byte
	p.Sum(&tag)
	return tag
}

// AeadEncrypt is RFC 8439 ChaCha20-Poly1305. It returns ciphertext and the 16-byte tag separately.
func AeadEncrypt(key, nonce, aad, pt []byte) (ct []byte, tag [16]byte, err error) {
	if len(key) != 32 || len(nonce) != 12 {
		return nil, tag, ErrParam
	}
	var k [32]byte
	copy(k[:], key)
	ct = make([]byte, len(pt))
	ChaCha20(key, nonce, 1, pt, ct)
	tag = aeadTag(&k, nonce, aad, ct)
	Wipe(k[:])
	return ct, tag, nil
}

// AeadDecrypt verifies tag and returns the plaintext, or ErrAuth.
func AeadDecrypt(key, nonce, aad, ct, tag []byte) ([]byte, error) {
	if len(key) != 32 || len(nonce) != 12 || len(tag) != 16 {
		return nil, ErrParam
	}
	var k [32]byte
	copy(k[:], key)
	exp := aeadTag(&k, nonce, aad, ct)
	Wipe(k[:])
	if !CtEq(exp[:], tag) {
		return nil, ErrAuth
	}
	pt := make([]byte, len(ct))
	ChaCha20(key, nonce, 1, ct, pt)
	return pt, nil
}

// Seal appends ct||tag (the common combined layout).
func Seal(key, nonce, aad, pt []byte) ([]byte, error) {
	ct, tag, err := AeadEncrypt(key, nonce, aad, pt)
	if err != nil {
		return nil, err
	}
	return append(ct, tag[:]...), nil
}

// Open reverses Seal.
func Open(key, nonce, aad, ctTag []byte) ([]byte, error) {
	if len(ctTag) < 16 {
		return nil, ErrAuth
	}
	n := len(ctTag) - 16
	return AeadDecrypt(key, nonce, aad, ctTag[:n], ctTag[n:])
}
