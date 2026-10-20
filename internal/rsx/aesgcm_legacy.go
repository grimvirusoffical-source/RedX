package rsx

// AES-256-GCM, DECRYPT ONLY. It exists solely to read data that was stored with
// AES-256-GCM before the move to Red-SecretsXAI (migration reader). There is no
// encrypt entry point on purpose: new data uses ChaCha20-Poly1305 formats.
//
// Implemented from FIPS-197 and NIST SP 800-38D without lookup tables: the S-box is
// computed as the GF(2^8) inverse followed by the affine map, and GHASH multiplies
// bit by bit with masks, so timing does not depend on key or data. It is slow
// (roughly a few MB/s), which is fine for a one-time migration.

func gmul8(a, b byte) byte {
	var p byte
	for i := 0; i < 8; i++ {
		p ^= -(b & 1) & a
		hi := -(a >> 7)
		a = a<<1 ^ (hi & 0x1b)
		b >>= 1
	}
	return p
}

func gfInv8(a byte) byte { // a^254; inv(0) = 0
	r, x := byte(1), a
	for i := 0; i < 7; i++ {
		x = gmul8(x, x)
		r = gmul8(r, x)
	}
	return r
}

func aesSbox(x byte) byte {
	b := gfInv8(x)
	rot := func(v byte, n uint) byte { return v<<n | v>>(8-n) }
	return b ^ rot(b, 1) ^ rot(b, 2) ^ rot(b, 3) ^ rot(b, 4) ^ 0x63
}

type aes256 struct{ rk [60]uint32 }

func newAES256(key []byte) *aes256 {
	a := &aes256{}
	for i := 0; i < 8; i++ {
		a.rk[i] = rd32(key[4*i:])
	}
	sub := func(w uint32) uint32 {
		return uint32(aesSbox(byte(w>>24)))<<24 | uint32(aesSbox(byte(w>>16)))<<16 | uint32(aesSbox(byte(w>>8)))<<8 | uint32(aesSbox(byte(w)))
	}
	rcon := byte(1)
	for i := 8; i < 60; i++ {
		t := a.rk[i-1]
		if i%8 == 0 {
			t = sub(t<<8|t>>24) ^ uint32(rcon)<<24
			rcon = gmul8(rcon, 2)
		} else if i%8 == 4 {
			t = sub(t)
		}
		a.rk[i] = a.rk[i-8] ^ t
	}
	return a
}

func (a *aes256) encryptBlock(dst, src []byte) {
	var s [16]byte
	for c := 0; c < 4; c++ {
		be32(s[4*c:], rd32(src[4*c:])^a.rk[c])
	}
	for r := 1; r <= 14; r++ {
		for i := range s {
			s[i] = aesSbox(s[i])
		}
		// ShiftRows (state is column-major: s[4*c + row])
		var t [16]byte
		for c := 0; c < 4; c++ {
			for row := 0; row < 4; row++ {
				t[4*c+row] = s[4*((c+row)%4)+row]
			}
		}
		if r != 14 { // MixColumns
			for c := 0; c < 4; c++ {
				a0, a1, a2, a3 := t[4*c], t[4*c+1], t[4*c+2], t[4*c+3]
				t[4*c] = gmul8(a0, 2) ^ gmul8(a1, 3) ^ a2 ^ a3
				t[4*c+1] = a0 ^ gmul8(a1, 2) ^ gmul8(a2, 3) ^ a3
				t[4*c+2] = a0 ^ a1 ^ gmul8(a2, 2) ^ gmul8(a3, 3)
				t[4*c+3] = gmul8(a0, 3) ^ a1 ^ a2 ^ gmul8(a3, 2)
			}
		}
		for c := 0; c < 4; c++ {
			be32(s[4*c:], rd32(t[4*c:])^a.rk[4*r+c])
		}
	}
	copy(dst, s[:])
	Wipe(s[:])
}

// ghashMul: x = x * h in GF(2^128) with the GCM bit order, constant time.
func ghashMul(x *[2]uint64, h [2]uint64) {
	var z [2]uint64
	v := h
	for i := 0; i < 128; i++ {
		bit := (x[i/64] >> (63 - uint(i%64))) & 1
		m := -bit
		z[0] ^= v[0] & m
		z[1] ^= v[1] & m
		lsb := v[1] & 1
		v[1] = v[1]>>1 | v[0]<<63
		v[0] = v[0] >> 1
		v[0] ^= 0xe100000000000000 & -lsb
	}
	*x = z
}

func ghashUpdate(y *[2]uint64, h [2]uint64, data []byte) {
	for len(data) > 0 {
		var blk [16]byte
		n := copy(blk[:], data)
		data = data[n:]
		y[0] ^= rd64(blk[0:])
		y[1] ^= rd64(blk[8:])
		ghashMul(y, h)
	}
}

// AES256GCMOpenLegacy decrypts and verifies AES-256-GCM (16-byte tag). The nonce may
// be any non-empty length (12 bytes is the normal case). It returns ErrAuth on any
// mismatch and never returns unauthenticated plaintext.
func AES256GCMOpenLegacy(key, nonce, aad, ct, tag []byte) ([]byte, error) {
	if len(key) != 32 || len(nonce) == 0 || len(tag) != 16 {
		return nil, ErrParam
	}
	a := newAES256(key)
	defer wipe32(a.rk[:])
	var hb [16]byte
	a.encryptBlock(hb[:], hb[:])
	h := [2]uint64{rd64(hb[0:]), rd64(hb[8:])}
	var j0 [16]byte
	if len(nonce) == 12 {
		copy(j0[:], nonce)
		j0[15] = 1
	} else {
		var y [2]uint64
		ghashUpdate(&y, h, nonce)
		var lb [16]byte
		be64(lb[8:], uint64(len(nonce))*8)
		ghashUpdate(&y, h, lb[:])
		be64(j0[0:], y[0])
		be64(j0[8:], y[1])
	}
	var y [2]uint64
	ghashUpdate(&y, h, aad)
	ghashUpdate(&y, h, ct)
	var lb [16]byte
	be64(lb[0:], uint64(len(aad))*8)
	be64(lb[8:], uint64(len(ct))*8)
	ghashUpdate(&y, h, lb[:])
	var ek [16]byte
	a.encryptBlock(ek[:], j0[:])
	var exp [16]byte
	be64(exp[0:], y[0])
	be64(exp[8:], y[1])
	for i := range exp {
		exp[i] ^= ek[i]
	}
	if !CtEq(exp[:], tag) {
		return nil, ErrAuth
	}
	pt := make([]byte, len(ct))
	ctr := j0
	inc := func() {
		c := rd32(ctr[12:]) + 1
		be32(ctr[12:], c)
	}
	var ks [16]byte
	for off := 0; off < len(ct); off += 16 {
		inc()
		a.encryptBlock(ks[:], ctr[:])
		for i := 0; i < 16 && off+i < len(ct); i++ {
			pt[off+i] = ct[off+i] ^ ks[i]
		}
	}
	Wipe(ks[:])
	return pt, nil
}

// aes256EncryptBlockForTest exposes the block function to the FIPS-197 KAT only.
func aes256EncryptBlockForTest(key, in []byte) []byte {
	out := make([]byte, 16)
	newAES256(key).encryptBlock(out, in)
	return out
}
