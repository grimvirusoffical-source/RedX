package rsx

import (
	"math/bits"
	"sync"
	"sync/atomic"
)

type a2block [128]uint64

var argon2MemCap atomic.Uint32

func init() { argon2MemCap.Store(Argon2MAccept) }

// SetArgon2MemCap sets the process-wide accept cap in KiB (like rsx_argon2_set_mem_cap).
func SetArgon2MemCap(mKiB uint32) error {
	if mKiB < 8 || mKiB > Argon2MMax {
		return ErrParam
	}
	argon2MemCap.Store(mKiB)
	return nil
}

// Argon2MemCap returns the current accept cap in KiB.
func Argon2MemCap() uint32 { return argon2MemCap.Load() }

// Argon2id is RFC 9106 Argon2id v1.3.
func Argon2id(pw, salt []byte, t, mKiB, p uint32, outLen int) ([]byte, error) {
	return Argon2idExt(pw, salt, nil, nil, t, mKiB, p, outLen)
}

func blamkaG(a, b, c, d *uint64) {
	fBlaMka := func(x, y uint64) uint64 { return x + y + 2*uint64(uint32(x))*uint64(uint32(y)) }
	*a = fBlaMka(*a, *b)
	*d = bits.RotateLeft64(*d^*a, -32)
	*c = fBlaMka(*c, *d)
	*b = bits.RotateLeft64(*b^*c, -24)
	*a = fBlaMka(*a, *b)
	*d = bits.RotateLeft64(*d^*a, -16)
	*c = fBlaMka(*c, *d)
	*b = bits.RotateLeft64(*b^*c, -63)
}

func blamkaP(v []*uint64) {
	blamkaG(v[0], v[4], v[8], v[12])
	blamkaG(v[1], v[5], v[9], v[13])
	blamkaG(v[2], v[6], v[10], v[14])
	blamkaG(v[3], v[7], v[11], v[15])
	blamkaG(v[0], v[5], v[10], v[15])
	blamkaG(v[1], v[6], v[11], v[12])
	blamkaG(v[2], v[7], v[8], v[13])
	blamkaG(v[3], v[4], v[9], v[14])
}

// fillBlock: out = G(ref, prev) (xor into out when withXor).
func fillBlock(out, ref, prev *a2block, withXor bool) {
	var r, z a2block
	for i := range r {
		r[i] = ref[i] ^ prev[i]
	}
	z = r
	var ptr [16]*uint64
	for i := 0; i < 8; i++ {
		for j := 0; j < 16; j++ {
			ptr[j] = &r[16*i+j]
		}
		blamkaP(ptr[:])
	}
	for i := 0; i < 8; i++ {
		for j := 0; j < 8; j++ {
			ptr[2*j] = &r[2*i+16*j]
			ptr[2*j+1] = &r[2*i+16*j+1]
		}
		blamkaP(ptr[:])
	}
	if withXor {
		for i := range out {
			out[i] ^= z[i] ^ r[i]
		}
	} else {
		for i := range out {
			out[i] = z[i] ^ r[i]
		}
	}
}

// Argon2idExt adds the optional secret K and associated data X (RFC 9106 §3.1).
func Argon2idExt(pw, salt, secret, ad []byte, t, mKiB, p uint32, outLen int) ([]byte, error) {
	if len(salt) < 8 || outLen < 4 {
		return nil, ErrParam
	}
	if t < 1 || t > Argon2TMax || p < 1 || p > Argon2PMax {
		return nil, ErrRange
	}
	if mKiB < 8*p || mKiB > Argon2MMax || mKiB > argon2MemCap.Load() {
		return nil, ErrRange
	}
	if avail := memAvailableKiB(); avail != 0 && uint64(mKiB)+16*1024 > avail {
		return nil, ErrRange
	}
	const sync4 = 4
	q := mKiB / (sync4 * p)
	m := q * sync4 * p
	if m < 8*p || q < 2 {
		return nil, ErrRange
	}
	laneLen := m / p
	segLen := laneLen / sync4

	// H0
	h, _ := NewBLAKE2b(64, nil)
	var w4 [4]byte
	put := func(v uint32) { putLe32(w4[:], v); h.Write(w4[:]) }
	putb := func(b []byte) { put(uint32(len(b))); h.Write(b) }
	put(p)
	put(uint32(outLen))
	put(mKiB)
	put(t)
	put(0x13)
	put(2)
	putb(pw)
	putb(salt)
	putb(secret)
	putb(ad)
	h0 := h.Sum(nil)

	B := make([]a2block, m)
	var tmp [72]byte
	var bh [1024]byte
	for lane := uint32(0); lane < p; lane++ {
		copy(tmp[:], h0)
		for k := uint32(0); k < 2; k++ {
			putLe32(tmp[64:], k)
			putLe32(tmp[68:], lane)
			blake2bLong(bh[:], tmp[:])
			blk := &B[lane*laneLen+k]
			for i := range blk {
				blk[i] = le64(bh[8*i:])
			}
		}
	}
	Wipe(tmp[:])
	Wipe(bh[:])
	Wipe(h0)

	fillLane := func(pass, slice, lane uint32) {
		start := uint32(0)
		if pass == 0 && slice == 0 {
			start = 2
		}
		dataIndep := pass == 0 && slice < sync4/2
		var addr, input, zero a2block
		if dataIndep {
			input[0], input[1], input[2] = uint64(pass), uint64(lane), uint64(slice)
			input[3], input[4], input[5] = uint64(m), uint64(t), 2
		}
		for i := start; i < segLen; i++ {
			cur := lane*laneLen + slice*segLen + i
			prevIdx := cur - 1
			if cur%laneLen == 0 {
				prevIdx = cur + laneLen - 1
			}
			prev := &B[prevIdx]
			var pseudo uint64
			if dataIndep {
				if i%128 == 0 || i == start {
					input[6]++
					fillBlock(&addr, &zero, &input, false)
					fillBlock(&addr, &zero, &addr, false)
				}
				pseudo = addr[i%128]
			} else {
				pseudo = prev[0]
			}
			refLane := uint32(pseudo>>32) % p
			if pass == 0 && slice == 0 {
				refLane = lane
			}
			var area uint32
			if pass == 0 {
				if refLane == lane {
					area = slice*segLen + i - 1
				} else {
					area = slice * segLen
					if i == 0 {
						area--
					}
				}
			} else {
				if refLane == lane {
					area = laneLen - segLen + i - 1
				} else {
					area = laneLen - segLen
					if i == 0 {
						area--
					}
				}
			}
			x := uint64(uint32(pseudo))
			y := (x * x) >> 32
			z := uint64(area) - 1 - ((uint64(area) * y) >> 32)
			var refIdx uint32
			if pass == 0 {
				refIdx = uint32(z)
			} else {
				refIdx = (((slice+1)%sync4)*segLen + uint32(z)) % laneLen
			}
			fillBlock(&B[cur], &B[refLane*laneLen+refIdx], prev, pass != 0)
		}
		wipe64(addr[:])
	}
	for pass := uint32(0); pass < t; pass++ {
		for slice := uint32(0); slice < sync4; slice++ {
			if p == 1 {
				fillLane(pass, slice, 0)
				continue
			}
			var wg sync.WaitGroup
			for lane := uint32(0); lane < p; lane++ {
				wg.Add(1)
				go func(l uint32) { defer wg.Done(); fillLane(pass, slice, l) }(lane)
			}
			wg.Wait()
		}
	}
	final := B[laneLen-1]
	for lane := uint32(1); lane < p; lane++ {
		last := &B[lane*laneLen+laneLen-1]
		for i := range final {
			final[i] ^= last[i]
		}
	}
	for i := range final {
		putLe64(bh[8*i:], final[i])
	}
	out := make([]byte, outLen)
	blake2bLong(out, bh[:])
	for i := range B {
		wipe64(B[i][:])
	}
	wipe64(final[:])
	Wipe(bh[:])
	return out, nil
}
