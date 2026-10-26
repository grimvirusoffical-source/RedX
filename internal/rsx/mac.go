package rsx

// HMAC is a streaming HMAC over any Hash in this package.
type HMAC struct {
	inner, outer Hash
	opad         []byte
	ipad         []byte
}

// NewHMAC returns HMAC keyed with key over the hash produced by newHash.
func NewHMAC(newHash func() Hash, key []byte) *HMAC {
	in, out := newHash(), newHash()
	bs := in.BlockSize()
	k := make([]byte, bs)
	if len(key) > bs {
		h := newHash()
		h.Write(key)
		h.Sum(k[:0])
	} else {
		copy(k, key)
	}
	m := &HMAC{inner: in, outer: out, ipad: make([]byte, bs), opad: make([]byte, bs)}
	for i := range k {
		m.ipad[i] = k[i] ^ 0x36
		m.opad[i] = k[i] ^ 0x5c
	}
	Wipe(k)
	m.Reset()
	return m
}
func (m *HMAC) Reset()                      { m.inner.Reset(); m.inner.Write(m.ipad) }
func (m *HMAC) Write(p []byte) (int, error) { return m.inner.Write(p) }
func (m *HMAC) Size() int                   { return m.outer.Size() }
func (m *HMAC) BlockSize() int              { return m.inner.BlockSize() }
func (m *HMAC) Sum(b []byte) []byte {
	ih := m.inner.Sum(nil)
	m.outer.Reset()
	m.outer.Write(m.opad)
	m.outer.Write(ih)
	Wipe(ih)
	return m.outer.Sum(b)
}

func newSHA256Hash() Hash { return NewSHA256() }
func newSHA1Hash() Hash   { return NewSHA1() }
func newSHA512Hash() Hash { return NewSHA512() }

// HmacSha256 returns HMAC-SHA256(key, msg).
func HmacSha256(key, msg []byte) [32]byte {
	m := NewHMAC(newSHA256Hash, key)
	m.Write(msg)
	var o [32]byte
	m.Sum(o[:0])
	return o
}

// HmacSha1 returns HMAC-SHA1(key, msg). It exists for TOTP/HOTP only.
func HmacSha1(key, msg []byte) [20]byte {
	m := NewHMAC(newSHA1Hash, key)
	m.Write(msg)
	var o [20]byte
	m.Sum(o[:0])
	return o
}

// HkdfSha256 is RFC 5869 HKDF with SHA-256. An empty salt means 32 zero bytes.
func HkdfSha256(ikm, salt, info []byte, outLen int) ([]byte, error) {
	if outLen < 0 || outLen > 255*32 {
		return nil, ErrParam
	}
	if len(salt) == 0 {
		salt = make([]byte, 32)
	}
	prk := HmacSha256(salt, ikm)
	out := make([]byte, 0, outLen)
	var t []byte
	for ctr := byte(1); len(out) < outLen; ctr++ {
		m := NewHMAC(newSHA256Hash, prk[:])
		m.Write(t)
		m.Write(info)
		m.Write([]byte{ctr})
		t = m.Sum(t[:0])
		need := outLen - len(out)
		if need > 32 {
			need = 32
		}
		out = append(out, t[:need]...)
	}
	Wipe(prk[:])
	Wipe(t)
	return out, nil
}

func hkdf32(ikm, salt []byte, info string) [32]byte {
	o, _ := HkdfSha256(ikm, salt, []byte(info), 32)
	var r [32]byte
	copy(r[:], o)
	Wipe(o)
	return r
}

// Pbkdf2Sha256 is RFC 8018 PBKDF2 with HMAC-SHA256.
func Pbkdf2Sha256(pw, salt []byte, iters uint32, outLen int) ([]byte, error) {
	if iters == 0 || outLen <= 0 {
		return nil, ErrParam
	}
	prf := NewHMAC(newSHA256Hash, pw)
	out := make([]byte, 0, outLen)
	var u, acc [32]byte
	for blk := uint32(1); len(out) < outLen; blk++ {
		prf.Reset()
		prf.Write(salt)
		var be [4]byte
		be32(be[:], blk)
		prf.Write(be[:])
		prf.Sum(u[:0])
		acc = u
		for j := uint32(1); j < iters; j++ {
			prf.Reset()
			prf.Write(u[:])
			prf.Sum(u[:0])
			for k := range acc {
				acc[k] ^= u[k]
			}
		}
		need := outLen - len(out)
		if need > 32 {
			need = 32
		}
		out = append(out, acc[:need]...)
	}
	Wipe(u[:])
	Wipe(acc[:])
	return out, nil
}

// HOTP is RFC 4226 (HMAC-SHA1, dynamic truncation) with `digits` decimal digits (6..8).
func HOTP(key []byte, counter uint64, digits int) (string, error) {
	if digits < 6 || digits > 8 {
		return "", ErrParam
	}
	var c [8]byte
	be64(c[:], counter)
	h := HmacSha1(key, c[:])
	off := h[19] & 0x0f
	bin := (uint32(h[off])&0x7f)<<24 | uint32(h[off+1])<<16 | uint32(h[off+2])<<8 | uint32(h[off+3])
	mod := uint32(1)
	for i := 0; i < digits; i++ {
		mod *= 10
	}
	v := bin % mod
	s := make([]byte, digits)
	for i := digits - 1; i >= 0; i-- {
		s[i] = byte('0' + v%10)
		v /= 10
	}
	return string(s), nil
}

// TOTP is RFC 6238 with HMAC-SHA1: T = floor((unix - t0) / step).
func TOTP(key []byte, unix, t0 int64, step int64, digits int) (string, error) {
	if step <= 0 || unix < t0 {
		return "", ErrParam
	}
	return HOTP(key, uint64((unix-t0)/step), digits)
}

// TOTPVerify checks code against the TOTP for unix, allowing +/- skew steps, in constant time per candidate.
func TOTPVerify(key []byte, code string, unix, t0, step int64, digits, skew int) bool {
	ok := false
	for d := -skew; d <= skew; d++ {
		u := unix + int64(d)*step
		if u < t0 {
			continue
		}
		c, err := TOTP(key, u, t0, step, digits)
		if err == nil && CtEq([]byte(c), []byte(code)) {
			ok = true
		}
	}
	return ok
}
