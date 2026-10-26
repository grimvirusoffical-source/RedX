package rsx

import "math/bits"

// Ed25519 (RFC 8032), implemented from the specification.
// Field: GF(2^255-19), five 51-bit limbs. Group: twisted Edwards, extended coordinates,
// the complete unified addition formula (no exceptional cases). Secret scalar
// multiplication is a fixed 256-step double-and-add with constant-time selection.

const (
	Ed25519PublicKeySize  = 32
	Ed25519PrivateKeySize = 64 // seed || public key (RFC 8032 / common layout)
	Ed25519SeedSize       = 32
	Ed25519SignatureSize  = 64
)

type fe [5]uint64

const mask51 = (1 << 51) - 1

func feAdd(o, a, b *fe) {
	for i := range o {
		o[i] = a[i] + b[i]
	}
}

// feSub computes a - b + 2p (keeps limbs positive).
func feSub(o, a, b *fe) {
	o[0] = a[0] + 0xfffffffffffda - b[0]
	o[1] = a[1] + 0xffffffffffffe - b[1]
	o[2] = a[2] + 0xffffffffffffe - b[2]
	o[3] = a[3] + 0xffffffffffffe - b[3]
	o[4] = a[4] + 0xffffffffffffe - b[4]
	feCarry(o)
}

func feCarry(o *fe) {
	c := o[0] >> 51
	o[0] &= mask51
	o[1] += c
	c = o[1] >> 51
	o[1] &= mask51
	o[2] += c
	c = o[2] >> 51
	o[2] &= mask51
	o[3] += c
	c = o[3] >> 51
	o[3] &= mask51
	o[4] += c
	c = o[4] >> 51
	o[4] &= mask51
	o[0] += c * 19
}

type u128 struct{ lo, hi uint64 }

func mulAcc(acc *u128, a, b uint64) {
	hi, lo := bits.Mul64(a, b)
	var c uint64
	acc.lo, c = bits.Add64(acc.lo, lo, 0)
	acc.hi += hi + c
}

func (x u128) shr51() uint64 { return x.lo>>51 | x.hi<<13 }

func feMul(o, a, b *fe) {
	a0, a1, a2, a3, a4 := a[0], a[1], a[2], a[3], a[4]
	b0, b1, b2, b3, b4 := b[0], b[1], b[2], b[3], b[4]
	b1_19, b2_19, b3_19, b4_19 := b1*19, b2*19, b3*19, b4*19
	var r0, r1, r2, r3, r4 u128
	mulAcc(&r0, a0, b0)
	mulAcc(&r0, a1, b4_19)
	mulAcc(&r0, a2, b3_19)
	mulAcc(&r0, a3, b2_19)
	mulAcc(&r0, a4, b1_19)
	mulAcc(&r1, a0, b1)
	mulAcc(&r1, a1, b0)
	mulAcc(&r1, a2, b4_19)
	mulAcc(&r1, a3, b3_19)
	mulAcc(&r1, a4, b2_19)
	mulAcc(&r2, a0, b2)
	mulAcc(&r2, a1, b1)
	mulAcc(&r2, a2, b0)
	mulAcc(&r2, a3, b4_19)
	mulAcc(&r2, a4, b3_19)
	mulAcc(&r3, a0, b3)
	mulAcc(&r3, a1, b2)
	mulAcc(&r3, a2, b1)
	mulAcc(&r3, a3, b0)
	mulAcc(&r3, a4, b4_19)
	mulAcc(&r4, a0, b4)
	mulAcc(&r4, a1, b3)
	mulAcc(&r4, a2, b2)
	mulAcc(&r4, a3, b1)
	mulAcc(&r4, a4, b0)
	feReduceWide(o, &r0, &r1, &r2, &r3, &r4)
}

func feReduceWide(o *fe, r0, r1, r2, r3, r4 *u128) {
	c0 := r0.shr51()
	h0 := r0.lo & mask51
	var c uint64
	r1.lo, c = bits.Add64(r1.lo, c0, 0)
	r1.hi += c
	c1 := r1.shr51()
	h1 := r1.lo & mask51
	r2.lo, c = bits.Add64(r2.lo, c1, 0)
	r2.hi += c
	c2 := r2.shr51()
	h2 := r2.lo & mask51
	r3.lo, c = bits.Add64(r3.lo, c2, 0)
	r3.hi += c
	c3 := r3.shr51()
	h3 := r3.lo & mask51
	r4.lo, c = bits.Add64(r4.lo, c3, 0)
	r4.hi += c
	c4 := r4.shr51()
	h4 := r4.lo & mask51
	h0 += c4 * 19
	h1 += h0 >> 51
	h0 &= mask51
	o[0], o[1], o[2], o[3], o[4] = h0, h1, h2, h3, h4
}

func feSq(o, a *fe) { feMul(o, a, a) }

func feSqN(o, a *fe, n int) {
	feSq(o, a)
	for i := 1; i < n; i++ {
		feSq(o, o)
	}
}

// fePowP58 returns a^((p-5)/8) = a^(2^252-3); feInv returns a^(p-2).
func fePow2523(o, z *fe) {
	var t0, t1, t2 fe
	feSq(&t0, z)
	feSqN(&t1, &t0, 2)
	feMul(&t1, z, &t1)
	feMul(&t0, &t0, &t1)
	feSq(&t0, &t0)
	feMul(&t0, &t1, &t0)
	feSqN(&t1, &t0, 5)
	feMul(&t0, &t1, &t0)
	feSqN(&t1, &t0, 10)
	feMul(&t1, &t1, &t0)
	feSqN(&t2, &t1, 20)
	feMul(&t1, &t2, &t1)
	feSqN(&t1, &t1, 10)
	feMul(&t0, &t1, &t0)
	feSqN(&t1, &t0, 50)
	feMul(&t1, &t1, &t0)
	feSqN(&t2, &t1, 100)
	feMul(&t1, &t2, &t1)
	feSqN(&t1, &t1, 50)
	feMul(&t0, &t1, &t0)
	feSqN(&t0, &t0, 2)
	feMul(o, &t0, z)
}

func feInv(o, z *fe) {
	var t0, t1, t2, t3 fe
	feSq(&t0, z)
	feSqN(&t1, &t0, 2)
	feMul(&t1, z, &t1)
	feMul(&t0, &t0, &t1)
	feSq(&t2, &t0)
	feMul(&t1, &t1, &t2)
	feSqN(&t2, &t1, 5)
	feMul(&t1, &t2, &t1)
	feSqN(&t2, &t1, 10)
	feMul(&t2, &t2, &t1)
	feSqN(&t3, &t2, 20)
	feMul(&t2, &t3, &t2)
	feSqN(&t2, &t2, 10)
	feMul(&t1, &t2, &t1)
	feSqN(&t2, &t1, 50)
	feMul(&t2, &t2, &t1)
	feSqN(&t3, &t2, 100)
	feMul(&t2, &t3, &t2)
	feSqN(&t2, &t2, 50)
	feMul(&t1, &t2, &t1)
	feSqN(&t1, &t1, 5)
	feMul(o, &t1, &t0)
}

func feFromBytes(o *fe, b []byte) {
	o[0] = le64(b[0:]) & mask51
	o[1] = (le64(b[6:]) >> 3) & mask51
	o[2] = (le64(b[12:]) >> 6) & mask51
	o[3] = (le64(b[19:]) >> 1) & mask51
	o[4] = (le64(b[24:]) >> 12) & mask51
}

func feToBytes(b []byte, a *fe) {
	t := *a
	feCarry(&t)
	feCarry(&t)
	// now t < 2^255 + small; subtract p if t >= p
	q := (t[0] + 19) >> 51
	q = (t[1] + q) >> 51
	q = (t[2] + q) >> 51
	q = (t[3] + q) >> 51
	q = (t[4] + q) >> 51
	t[0] += 19 * q
	c := t[0] >> 51
	t[0] &= mask51
	t[1] += c
	c = t[1] >> 51
	t[1] &= mask51
	t[2] += c
	c = t[2] >> 51
	t[2] &= mask51
	t[3] += c
	c = t[3] >> 51
	t[3] &= mask51
	t[4] += c
	t[4] &= mask51
	var out [32]byte
	putLe64(out[0:], t[0]|t[1]<<51)
	putLe64(out[8:], t[1]>>13|t[2]<<38)
	putLe64(out[16:], t[2]>>26|t[3]<<25)
	putLe64(out[24:], t[3]>>39|t[4]<<12)
	copy(b, out[:])
}

func feIsZero(a *fe) bool {
	var b [32]byte
	feToBytes(b[:], a)
	return CtEq(b[:], make([]byte, 32))
}

func feIsNeg(a *fe) uint64 {
	var b [32]byte
	feToBytes(b[:], a)
	return uint64(b[0] & 1)
}

func feNeg(o, a *fe) { var z fe; feSub(o, &z, a) }

// feCmov sets o = a when c == 1 (c must be 0 or 1).
func feCmov(o, a *fe, c uint64) {
	m := -c
	for i := range o {
		o[i] ^= m & (o[i] ^ a[i])
	}
}

func feEq(a, b *fe) bool {
	var x, y [32]byte
	feToBytes(x[:], a)
	feToBytes(y[:], b)
	return CtEq(x[:], y[:])
}

var (
	feOne             = fe{1}
	edD, edD2, sqrtM1 fe
	edBase            edPoint
)

type edPoint struct{ X, Y, Z, T fe }

func init() {
	// d = -121665/121666
	var n, dd, inv fe
	n[0] = 121665
	dd[0] = 121666
	feInv(&inv, &dd)
	feMul(&edD, &n, &inv)
	feNeg(&edD, &edD)
	feAdd(&edD2, &edD, &edD)
	feCarry(&edD2)
	// sqrt(-1) = 2^((p-1)/4)
	var two fe
	two[0] = 2
	// (p-1)/4 = 2^253 - 5: compute 2^(2^252-3) squared... use pow2523(2)*... simpler: x = 2^((p-1)/4)
	// (p-1)/4 = 2*(2^252-3) + 1 -> x = (2^(2^252-3))^2 * 2
	var t fe
	fePow2523(&t, &two)
	feSq(&t, &t)
	feMul(&sqrtM1, &t, &two)
	var bb [32]byte
	bb[0] = 0x58
	for i := 1; i < 32; i++ {
		bb[i] = 0x66
	}
	if !edDecode(&edBase, bb[:]) {
		panic("rsx: ed25519 base point")
	}
}

func edIdentity(p *edPoint) { *p = edPoint{Y: feOne, Z: feOne} }

// edAdd is the complete unified addition for a = -1 (also correct for doubling).
func edAdd(o, p, q *edPoint) {
	var a, b, c, d, e, f, g, h, t fe
	feSub(&a, &p.Y, &p.X)
	feSub(&t, &q.Y, &q.X)
	feMul(&a, &a, &t)
	feAdd(&b, &p.Y, &p.X)
	feAdd(&t, &q.Y, &q.X)
	feMul(&b, &b, &t)
	feMul(&c, &p.T, &q.T)
	feMul(&c, &c, &edD2)
	feMul(&d, &p.Z, &q.Z)
	feAdd(&d, &d, &d)
	feSub(&e, &b, &a)
	feSub(&f, &d, &c)
	feAdd(&g, &d, &c)
	feAdd(&h, &b, &a)
	feMul(&o.X, &e, &f)
	feMul(&o.Y, &g, &h)
	feMul(&o.T, &e, &h)
	feMul(&o.Z, &f, &g)
}

func edCmov(o, a *edPoint, c uint64) {
	feCmov(&o.X, &a.X, c)
	feCmov(&o.Y, &a.Y, c)
	feCmov(&o.Z, &a.Z, c)
	feCmov(&o.T, &a.T, c)
}

// edScalarMult computes [k]P with a fixed sequence of operations (k is 32 bytes little-endian).
func edScalarMult(o *edPoint, k []byte, p *edPoint) {
	var q, r edPoint
	edIdentity(&q)
	for i := 255; i >= 0; i-- {
		edAdd(&q, &q, &q)
		edAdd(&r, &q, p)
		bit := uint64(k[i>>3]>>(uint(i)&7)) & 1
		edCmov(&q, &r, bit)
	}
	*o = q
}

func edEncode(b []byte, p *edPoint) {
	var zi, x, y fe
	feInv(&zi, &p.Z)
	feMul(&x, &p.X, &zi)
	feMul(&y, &p.Y, &zi)
	feToBytes(b, &y)
	b[31] ^= byte(feIsNeg(&x) << 7)
}

// edDecode implements RFC 8032 §5.1.3; it rejects non-canonical y (y >= p).
func edDecode(p *edPoint, b []byte) bool {
	if len(b) != 32 {
		return false
	}
	var yb [32]byte
	copy(yb[:], b)
	sign := yb[31] >> 7
	yb[31] &= 0x7f
	var y fe
	feFromBytes(&y, yb[:])
	var chk [32]byte
	feToBytes(chk[:], &y)
	if !CtEq(chk[:], yb[:]) {
		return false
	}
	var u, v, y2, v3, v7, x, vx2, t fe
	feSq(&y2, &y)
	feSub(&u, &y2, &feOne)
	feMul(&v, &y2, &edD)
	feAdd(&v, &v, &feOne)
	feCarry(&v)
	feSq(&v3, &v)
	feMul(&v3, &v3, &v)
	feSq(&v7, &v3)
	feMul(&v7, &v7, &v)
	feMul(&t, &u, &v7)
	fePow2523(&t, &t)
	feMul(&x, &u, &v3)
	feMul(&x, &x, &t)
	feSq(&vx2, &x)
	feMul(&vx2, &vx2, &v)
	var negu fe
	feNeg(&negu, &u)
	if !feEq(&vx2, &u) {
		if !feEq(&vx2, &negu) {
			return false
		}
		feMul(&x, &x, &sqrtM1)
	}
	if feIsZero(&x) && sign == 1 {
		return false
	}
	if feIsNeg(&x) != uint64(sign) {
		feNeg(&x, &x)
	}
	p.X, p.Y, p.Z = x, y, feOne
	feMul(&p.T, &x, &y)
	return true
}

// ---- scalars mod L = 2^252 + 27742317777372353535851937790883648493 ----

var scL = [4]uint64{0x5812631a5cf5d3ed, 0x14def9dea2f79cd6, 0, 0x1000000000000000}

// scReduce reduces a 512-bit little-endian value (8 limbs) mod L, bit-serially and in constant time.
func scReduce(x [8]uint64) [4]uint64 {
	var r [4]uint64
	for i := 511; i >= 0; i-- {
		// r = 2r + bit (r < L < 2^253, so 2r+1 < 2^254 fits)
		r[3] = r[3]<<1 | r[2]>>63
		r[2] = r[2]<<1 | r[1]>>63
		r[1] = r[1]<<1 | r[0]>>63
		r[0] = r[0]<<1 | (x[i>>6]>>(uint(i)&63))&1
		var t [4]uint64
		var b uint64
		t[0], b = bits.Sub64(r[0], scL[0], 0)
		t[1], b = bits.Sub64(r[1], scL[1], b)
		t[2], b = bits.Sub64(r[2], scL[2], b)
		t[3], b = bits.Sub64(r[3], scL[3], b)
		m := b - 1 // b==0 -> r >= L -> take t
		for j := 0; j < 4; j++ {
			r[j] = (r[j] &^ m) | (t[j] & m)
		}
	}
	return r
}

func scFromBytes64(b []byte) [4]uint64 {
	var x [8]uint64
	for i := 0; i < 8; i++ {
		x[i] = le64(b[8*i:])
	}
	return scReduce(x)
}

func scBytes(s [4]uint64) [32]byte {
	var o [32]byte
	for i := 0; i < 4; i++ {
		putLe64(o[8*i:], s[i])
	}
	return o
}

// scMulAdd returns (a*b + c) mod L.
func scMulAdd(a, b, c [4]uint64) [4]uint64 {
	var x [8]uint64
	for i := 0; i < 4; i++ {
		var carry uint64
		for j := 0; j < 4; j++ {
			hi, lo := bits.Mul64(a[i], b[j])
			var cc uint64
			lo, cc = bits.Add64(lo, x[i+j], 0)
			hi += cc
			lo, cc = bits.Add64(lo, carry, 0)
			hi += cc
			x[i+j] = lo
			carry = hi
		}
		x[i+4] = carry
	}
	var cc uint64
	for i := 0; i < 8; i++ {
		var ci uint64
		if i < 4 {
			ci = c[i]
		}
		x[i], cc = bits.Add64(x[i], ci, cc)
	}
	return scReduce(x)
}

// scCanonical reports whether the 32-byte s is < L.
func scCanonical(s []byte) bool {
	var v [4]uint64
	for i := 0; i < 4; i++ {
		v[i] = le64(s[8*i:])
	}
	_, b := bits.Sub64(v[0], scL[0], 0)
	_, b = bits.Sub64(v[1], scL[1], b)
	_, b = bits.Sub64(v[2], scL[2], b)
	_, b = bits.Sub64(v[3], scL[3], b)
	return b == 1
}

func edExpand(seed []byte) (a [32]byte, prefix [32]byte) {
	h := Sha512(seed)
	copy(a[:], h[:32])
	copy(prefix[:], h[32:])
	a[0] &= 248
	a[31] &= 127
	a[31] |= 64
	Wipe(h[:])
	return
}

// Ed25519KeyFromSeed returns the 64-byte private key (seed || public key) for a 32-byte seed.
func Ed25519KeyFromSeed(seed []byte) ([]byte, error) {
	if len(seed) != 32 {
		return nil, ErrParam
	}
	a, prefix := edExpand(seed)
	Wipe(prefix[:])
	var A edPoint
	edScalarMult(&A, a[:], &edBase)
	Wipe(a[:])
	priv := make([]byte, 64)
	copy(priv, seed)
	edEncode(priv[32:], &A)
	return priv, nil
}

// Ed25519GenerateKey returns (public, private) from fresh OS randomness.
func Ed25519GenerateKey() (pub, priv []byte, err error) {
	seed := make([]byte, 32)
	if err = Random(seed); err != nil {
		return nil, nil, err
	}
	priv, err = Ed25519KeyFromSeed(seed)
	Wipe(seed)
	if err != nil {
		return nil, nil, err
	}
	return append([]byte(nil), priv[32:]...), priv, nil
}

// Ed25519Sign signs msg with a 64-byte private key (seed || public key).
func Ed25519Sign(priv, msg []byte) ([]byte, error) {
	if len(priv) != 64 {
		return nil, ErrParam
	}
	a, prefix := edExpand(priv[:32])
	pub := priv[32:]
	h := NewSHA512()
	h.Write(prefix[:])
	h.Write(msg)
	r := scFromBytes64(h.Sum(nil))
	rb := scBytes(r)
	var R edPoint
	edScalarMult(&R, rb[:], &edBase)
	sig := make([]byte, 64)
	edEncode(sig[:32], &R)
	h.Reset()
	h.Write(sig[:32])
	h.Write(pub)
	h.Write(msg)
	k := scFromBytes64(h.Sum(nil))
	var av [4]uint64
	for i := 0; i < 4; i++ {
		av[i] = le64(a[8*i:])
	}
	s := scBytes(scMulAdd(k, av, r))
	copy(sig[32:], s[:])
	Wipe(a[:])
	Wipe(prefix[:])
	Wipe(rb[:])
	wipe64(av[:])
	return sig, nil
}

// Ed25519Verify reports whether sig is a valid RFC 8032 signature of msg by pub.
// It rejects non-canonical S (S >= L) and non-canonical or invalid encodings of A.
func Ed25519Verify(pub, msg, sig []byte) bool {
	if len(pub) != 32 || len(sig) != 64 || !scCanonical(sig[32:]) {
		return false
	}
	var A edPoint
	if !edDecode(&A, pub) {
		return false
	}
	h := NewSHA512()
	h.Write(sig[:32])
	h.Write(pub)
	h.Write(msg)
	kb := scBytes(scFromBytes64(h.Sum(nil)))
	// R' = [S]B - [k]A
	var sB, kA, negA, Rp edPoint
	edScalarMult(&sB, sig[32:], &edBase)
	negA = A
	feNeg(&negA.X, &A.X)
	feNeg(&negA.T, &A.T)
	edScalarMult(&kA, kb[:], &negA)
	edAdd(&Rp, &sB, &kA)
	var enc [32]byte
	edEncode(enc[:], &Rp)
	return CtEq(enc[:], sig[:32])
}
