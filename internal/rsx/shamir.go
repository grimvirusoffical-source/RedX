package rsx

// B4: Shamir k-of-n over GF(2^8) (polynomial 0x11B), constant-time field arithmetic.
// Share card "RSXS" v1: magic4 ver1 k1 n1 x1 set_id8 L1 y[L] check16  (33+L bytes).

func shamirCheck(secret, meta []byte) []byte {
	msg := make([]byte, 0, 26)
	msg = append(msg, "RSX shamir v1"...)
	msg = append(msg, meta...)
	msg = append(msg, byte(len(secret)))
	h := HmacSha256(secret, msg)
	return h[:16]
}

// ShamirShareLen is 33+L for an L-byte secret (1..64).
func ShamirShareLen(L int) (int, error) {
	if L < 1 || L > 64 {
		return 0, ErrParam
	}
	return 33 + L, nil
}

// ShamirSplit splits secret into n share cards, any k of which recover it.
func ShamirSplit(secret []byte, k, n int) ([][]byte, error) {
	L := len(secret)
	if L < 1 || L > 64 || k < 2 || n < k || n > 255 {
		return nil, ErrParam
	}
	setID := make([]byte, 8)
	coef := make([]byte, (k-1)*L)
	if Random(setID) != nil || Random(coef) != nil {
		return nil, ErrRNG
	}
	defer Wipe(coef)
	shares := make([][]byte, n)
	for i := 0; i < n; i++ {
		s := make([]byte, 33+L)
		x := byte(i + 1)
		copy(s, "RSXS")
		s[4], s[5], s[6], s[7] = 1, byte(k), byte(n), x
		copy(s[8:], setID)
		s[16] = byte(L)
		for j := 0; j < L; j++ {
			var acc byte
			for c := k - 1; c >= 1; c-- {
				acc = gmul8(acc^coef[(c-1)*L+j], x)
			}
			s[17+j] = acc ^ secret[j]
		}
		shares[i] = s
	}
	meta := append([]byte(nil), shares[0][4:16]...)
	meta[3] = 0
	tag := shamirCheck(secret, meta)
	for _, s := range shares {
		copy(s[17+L:], tag)
	}
	return shares, nil
}

// ShamirCombine recovers the secret; ErrAuth on wrong, mixed or forged shares, ErrRange if fewer than k.
func ShamirCombine(shares [][]byte) ([]byte, error) {
	if len(shares) < 2 || len(shares) > 255 {
		return nil, ErrParam
	}
	s0 := shares[0]
	if len(s0) < 34 || len(s0) > 97 {
		return nil, ErrParam
	}
	if string(s0[:4]) != "RSXS" || s0[4] != 1 {
		return nil, ErrFormat
	}
	L, k, n := int(s0[16]), int(s0[5]), int(s0[6])
	if L < 1 || L > 64 || len(s0) != 33+L || k < 2 || n < k {
		return nil, ErrFormat
	}
	if len(shares) < k {
		return nil, ErrRange
	}
	xs := make([]byte, k)
	for i := 0; i < k; i++ {
		s := shares[i]
		if len(s) != len(s0) || string(s[:4]) != "RSXS" || s[4] != 1 || int(s[5]) != k || int(s[6]) != n || int(s[16]) != L || string(s[8:16]) != string(s0[8:16]) {
			return nil, ErrFormat
		}
		if s[7] == 0 || int(s[7]) > n {
			return nil, ErrFormat
		}
		for j := 0; j < i; j++ {
			if xs[j] == s[7] {
				return nil, ErrFormat
			}
		}
		xs[i] = s[7]
	}
	out := make([]byte, L)
	for i := 0; i < k; i++ {
		num, den := byte(1), byte(1)
		for j := 0; j < k; j++ {
			if j != i {
				num = gmul8(num, xs[j])
				den = gmul8(den, xs[i]^xs[j])
			}
		}
		li := gmul8(num, gfInv8(den))
		for b := 0; b < L; b++ {
			out[b] ^= gmul8(shares[i][17+b], li)
		}
	}
	meta := append([]byte(nil), s0[4:16]...)
	meta[3] = 0
	tag := shamirCheck(out, meta)
	good := true
	for _, s := range shares {
		if len(s) != len(s0) || !CtEq(tag, s[17+L:]) {
			good = false
		}
	}
	if !good {
		Wipe(out)
		return nil, ErrAuth
	}
	return out, nil
}
