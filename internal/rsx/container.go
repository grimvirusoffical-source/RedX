package rsx

// ---------- RSXC v1 capability container + size bands (rsx_sealc / rsx_openc) ----------

const (
	BandCount = 10
	BandAuto  = -1
	BandNone  = -2

	CapPadded uint16 = 0x0001
	CapRSX3v2 uint16 = 0x0002
	CapOuter  uint16 = 0x0004
)

var bandPT = [BandCount]uint64{256, 1024, 4096, 16384, 65536, 262144, 1048576, 4194304, 16777216, 67108864}

const knownCaps = CapPadded | CapRSX3v2

func rsx3Size(ptLen, storedAAD uint64) uint64 {
	h := uint64(4+1+1+12+32+16+2) + storedAAD + 8 + 16
	chunks := ptLen/65536 + 1
	return h + ptLen + chunks*(3+16)
}

// BandPlaintext returns the inner framed plaintext size of a band (0 if invalid).
func BandPlaintext(band int) uint64 {
	if band < 0 || band >= BandCount {
		return 0
	}
	return bandPT[band]
}

// BandCapacity returns the user data capacity of a band.
func BandCapacity(band int) uint64 {
	if band < 0 || band >= BandCount {
		return 0
	}
	return bandPT[band] - 8
}

// BandTotalSize is the exact container size for a band and user AAD length.
func BandTotalSize(band int, userAAD int) uint64 {
	if band < 0 || band >= BandCount || userAAD > MaxAADLen-8 {
		return 0
	}
	return 8 + rsx3Size(bandPT[band], 8+uint64(userAAD))
}

// BandForLen returns the smallest band holding n bytes, or ErrRange.
func BandForLen(n int) (int, error) {
	for b := 0; b < BandCount; b++ {
		if uint64(n) <= bandPT[b]-8 {
			return b, nil
		}
	}
	return 0, ErrRange
}

// SealC seals data into an RSXC v1 container (band: 0..9, BandAuto or BandNone).
func (s *Session) SealC(aad, data []byte, band int) ([]byte, error) {
	if err := s.ok(); err != nil {
		return nil, err
	}
	if len(aad) > MaxAADLen-8 {
		return nil, ErrParam
	}
	hdr := []byte{'R', 'S', 'X', 'C', 1, 0xFF, 0, 0}
	caps := CapRSX3v2
	var ptLen uint64
	if band == BandNone {
		ptLen = 8 + uint64(len(data))
	} else {
		if band == BandAuto {
			b, err := BandForLen(len(data))
			if err != nil {
				return nil, err
			}
			band = b
		}
		if band < 0 || band >= BandCount {
			return nil, ErrParam
		}
		if uint64(len(data)) > bandPT[band]-8 {
			return nil, ErrRange
		}
		hdr[5] = byte(band)
		caps |= CapPadded
		ptLen = bandPT[band]
	}
	if ptLen > MaxBlob {
		return nil, ErrLimit
	}
	be16(hdr[6:], caps)
	pt := make([]byte, ptLen)
	be64(pt, uint64(len(data)))
	copy(pt[8:], data)
	inner, err := s.Seal3(append(append([]byte(nil), hdr...), aad...), pt)
	Wipe(pt)
	if err != nil {
		return nil, err
	}
	return append(hdr, inner...), nil
}

// PeekC returns the UNAUTHENTICATED header hint (ver, band, caps); OpenC is the authority.
func PeekC(blob []byte) (ver, band, caps uint32, err error) {
	if len(blob) < 8 || string(blob[:4]) != "RSXC" {
		return 0, 0, 0, ErrFormat
	}
	return uint32(blob[4]), uint32(blob[5]), uint32(rd16(blob[6:])), nil
}

// OpenC opens an RSXC v1 container; requiredCaps is the caller's policy (ErrDowngrade if unmet).
func (s *Session) OpenC(aad, blob []byte, requiredCaps uint32) ([]byte, uint32, error) {
	if err := s.ok(); err != nil {
		return nil, 0, err
	}
	if len(aad) > MaxAADLen-8 {
		return nil, 0, ErrParam
	}
	if len(blob) < 8 || string(blob[:4]) != "RSXC" || blob[4] != 1 {
		return nil, 0, ErrFormat
	}
	caps := rd16(blob[6:])
	if caps&^knownCaps != 0 || caps&CapRSX3v2 == 0 {
		return nil, 0, ErrFormat
	}
	if requiredCaps&^uint32(caps) != 0 {
		return nil, 0, ErrDowngrade
	}
	padded := caps&CapPadded != 0
	band := int(blob[5])
	if padded {
		if band >= BandCount || uint64(len(blob)) != BandTotalSize(band, len(aad)) {
			return nil, 0, ErrFormat
		}
	} else if band != 0xFF {
		return nil, 0, ErrFormat
	}
	pt, err := s.Open3(append(append([]byte(nil), blob[:8]...), aad...), blob[8:])
	if err != nil {
		return nil, 0, err
	}
	defer Wipe(pt)
	if len(pt) < 8 {
		return nil, 0, ErrAuth
	}
	n := rd64(pt)
	if n > uint64(len(pt)-8) {
		return nil, 0, ErrAuth
	}
	if padded {
		if uint64(len(pt)) != bandPT[band] {
			return nil, 0, ErrAuth
		}
		var acc byte
		for _, b := range pt[8+n:] {
			acc |= b
		}
		if acc != 0 {
			return nil, 0, ErrAuth
		}
	} else if n != uint64(len(pt)-8) {
		return nil, 0, ErrAuth
	}
	return append([]byte(nil), pt[8:8+n]...), uint32(caps), nil
}

// ---------- B7 outer ARX-Feistel layer (rsx_outer_wrap / unwrap) ----------

func feistelRound(r, k uint32) uint32 {
	x := r + k
	x ^= x<<7 | x>>25
	x += k<<13 | k>>19
	x ^= x<<17 | x>>15
	return x
}

func feistelSchedule(key []byte) [16]uint32 {
	rl := func(x uint32, n uint) uint32 { return x<<n | x>>(32-n) }
	a, b, c, d := le32(key[0:]), le32(key[4:]), le32(key[8:]), le32(key[12:])
	e, f, g, h := le32(key[16:]), le32(key[20:]), le32(key[24:]), le32(key[28:])
	var rk [16]uint32
	for i := 0; i < 16; i++ {
		a += rl(b^c, 5) + 0x9E3779B9*uint32(i+1)
		b ^= rl(d+e, 11)
		c += rl(f^g, 19)
		d ^= rl(h+a, 23)
		e += rl(a^b, 3)
		f ^= rl(c+d, 13)
		g += rl(e^f, 17)
		h ^= rl(g+a, 7)
		rk[i] = a ^ c ^ e ^ g
	}
	return rk
}

// feistel matches librsx's native little-endian word loads.
func feistel(key, buf []byte, inv bool) {
	if len(buf) < 8 {
		return
	}
	rk := feistelSchedule(key)
	n := len(buf) &^ 7
	for off := 0; off < n; off += 8 {
		L, R := le32(buf[off:]), le32(buf[off+4:])
		if !inv {
			for i := 0; i < 16; i++ {
				L, R = R, L^feistelRound(R, rk[i])
			}
		} else {
			for i := 15; i >= 0; i-- {
				R, L = L, R^feistelRound(L, rk[i])
			}
		}
		putLe32(buf[off:], L)
		putLe32(buf[off+4:], R)
	}
	wipe32(rk[:])
}

// OuterWrap applies the B7 outer layer to an AEAD blob: "RSXO" 01 salt16 || F(K_outer, inner).
func (s *Session) OuterWrap(inner []byte) ([]byte, error) {
	if err := s.ok(); err != nil {
		return nil, err
	}
	if len(inner) < 8 {
		return nil, ErrParam
	}
	o := make([]byte, 21+len(inner))
	copy(o, "RSXO")
	o[4] = 1
	if Random(o[5:21]) != nil {
		return nil, ErrRNG
	}
	k := hkdf32(s.kek[:], o[5:21], "RSXO v1")
	copy(o[21:], inner)
	feistel(k[:], o[21:], false)
	Wipe(k[:])
	return o, nil
}

// OuterUnwrap removes the outer layer (the inner AEAD then authenticates).
func (s *Session) OuterUnwrap(blob []byte) ([]byte, error) {
	if err := s.ok(); err != nil {
		return nil, err
	}
	if len(blob) < 29 || string(blob[:4]) != "RSXO" || blob[4] != 1 {
		return nil, ErrFormat
	}
	k := hkdf32(s.kek[:], blob[5:21], "RSXO v1")
	o := append([]byte(nil), blob[21:]...)
	feistel(k[:], o, true)
	Wipe(k[:])
	return o, nil
}

// ---------- legacy RSX1 / RSX2 whole-blob open (PBKDF2) ----------

const (
	legacyMinIters = 200000
	legacyMaxIters = 1000000
)

// Open1 opens a legacy RSX1 blob.
func Open1(pw, blob []byte) ([]byte, error) {
	if len(blob) < 41+32 || string(blob[:4]) != "RSX1" || blob[4] != 1 {
		return nil, ErrFormat
	}
	iters := rd32(blob[5:])
	if iters < legacyMinIters || iters > legacyMaxIters {
		return nil, ErrRange
	}
	salt, nonce := blob[9:25], blob[25:37]
	n := uint64(rd32(blob[37:]))
	need := 41 + n + 32
	if need > MaxBlob || uint64(len(blob)) > MaxBlob {
		return nil, ErrLimit
	}
	if uint64(len(blob)) != need {
		return nil, ErrFormat
	}
	master, _ := Pbkdf2Sha256(pw, salt, iters, 32)
	ek := HmacSha256(master, []byte("RSX1 enc"))
	mk := HmacSha256(master, []byte("RSX1 mac"))
	Wipe(master)
	exp := HmacSha256(mk[:], blob[:41+n])
	Wipe(mk[:])
	if !CtEq(exp[:], blob[41+n:]) {
		Wipe(ek[:])
		return nil, ErrAuth
	}
	pt := make([]byte, n)
	ChaCha20(ek[:], nonce, 1, blob[41:41+n], pt)
	Wipe(ek[:])
	return pt, nil
}

// Open2 opens a legacy RSX2 blob (password + 32-byte server key).
func Open2(pw, serverKey, blob []byte) ([]byte, error) {
	if len(serverKey) != 32 {
		return nil, ErrParam
	}
	if len(blob) < 53+32 || string(blob[:4]) != "RSX2" || blob[4] != 2 {
		return nil, ErrFormat
	}
	iters := rd32(blob[5:])
	if iters < legacyMinIters || iters > legacyMaxIters {
		return nil, ErrRange
	}
	fp, salt, nonce := blob[13:21], blob[21:37], blob[37:49]
	n := uint64(rd32(blob[49:]))
	need := 53 + n + 32
	if need > MaxBlob || uint64(len(blob)) > MaxBlob {
		return nil, ErrLimit
	}
	if uint64(len(blob)) != need {
		return nil, ErrFormat
	}
	fh := Sha256(append([]byte("RSX2 fp"), serverKey...))
	if !CtEq(fh[:8], fp) {
		return nil, ErrAuth
	}
	P, _ := Pbkdf2Sha256(pw, salt, iters, 32)
	ikm := append(P, serverKey...)
	okm, _ := HkdfSha256(ikm, salt, []byte("RSX2"), 64)
	Wipe(ikm)
	defer Wipe(okm)
	exp := HmacSha256(okm[32:], blob[:53+n])
	if !CtEq(exp[:], blob[53+n:]) {
		return nil, ErrAuth
	}
	pt := make([]byte, n)
	ChaCha20(okm[:32], nonce, 1, blob[53:53+n], pt)
	return pt, nil
}

// ---------- B9 duress / decoy multi-slot container ----------

const (
	rsxdN      = 8
	rsxdFilled = 0x01
)

// DuressSize returns the container size for a band (0 if invalid).
func DuressSize(band, nSlots int) uint64 {
	if band < 0 || band >= BandCount || nSlots < 2 || nSlots > 8 {
		return 0
	}
	if BandTotalSize(band, 0) < 16+rsxdN*(16+6+1) {
		return 0
	}
	return BandTotalSize(band, 0)
}

func duressDerive(pw, salt []byte, kp KDFParams) ([]byte, error) {
	k, err := Argon2id(pw, salt, kp.T, kp.M, kp.P, 32)
	if err != nil {
		if err == ErrRange {
			return nil, ErrRange
		}
		return nil, ErrParam
	}
	return k, nil
}

func duressSlot(K []byte) (int, [32]byte) {
	h := HmacSha256(K, []byte("RSXD idx"))
	idx := int(h[0]) % rsxdN
	var info [4]byte
	be32(info[:], uint32(idx))
	o, _ := HkdfSha256(K, info[:], []byte("RSXD slot"), 32)
	var ks [32]byte
	copy(ks[:], o)
	Wipe(o)
	return idx, ks
}

// DuressSeal seals one plaintext per password into a duress container (kp = Argon2id params).
func DuressSeal(passwords, plains [][]byte, nSlots, band int, kp KDFParams) ([]byte, error) {
	nk := len(passwords)
	if nk < 1 || nk > nSlots || len(plains) != nk || nSlots < 2 || nSlots > 8 || band < 0 || band >= BandCount {
		return nil, ErrParam
	}
	T := BandTotalSize(band, 0)
	if T < 16+rsxdN*32 {
		return nil, ErrRange
	}
	slotLen := int((T - 16) / rsxdN)
	ptLen := slotLen - 16
	if ptLen < 6 {
		return nil, ErrRange
	}
	for i := range passwords {
		if uint64(len(plains[i])) > uint64(ptLen-6) {
			return nil, ErrRange
		}
		for j := 0; j < i; j++ {
			if CtEq(passwords[i], passwords[j]) {
				return nil, ErrParam
			}
		}
	}
	blob := make([]byte, T)
	var keys [][32]byte
	var idxs []int
	placed := false
	for attempt := 0; attempt < 64 && !placed; attempt++ {
		if Random(blob) != nil {
			return nil, ErrRNG
		}
		used := [rsxdN]bool{}
		keys, idxs = keys[:0], idxs[:0]
		coll := false
		for i := 0; i < nk && !coll; i++ {
			K, err := duressDerive(passwords[i], blob[:16], kp)
			if err != nil {
				return nil, err
			}
			idx, ks := duressSlot(K)
			Wipe(K)
			if used[idx] {
				coll = true
			} else {
				used[idx] = true
				keys = append(keys, ks)
				idxs = append(idxs, idx)
			}
		}
		placed = !coll
	}
	if !placed {
		return nil, ErrParam
	}
	for i := 0; i < nk; i++ {
		pt := make([]byte, ptLen)
		nested := false
		for b2 := 0; b2 < BandCount; b2++ {
			if BandTotalSize(b2, 0) == uint64(len(plains[i])) {
				nested = true
			}
		}
		capB := ptLen - 6
		pt[0] = 1
		plen := uint32(len(plains[i]))
		if nested {
			pt[1] = rsxdFilled
			plen = uint32(capB)
		}
		be32(pt[2:], plen)
		copy(pt[6:], plains[i])
		if nested && capB > len(plains[i]) {
			if Random(pt[6+len(plains[i]):]) != nil {
				return nil, ErrRNG
			}
		}
		ct, tag, _ := AeadEncrypt(keys[i][:], make([]byte, 12), []byte("RSXD1"), pt)
		off := 16 + idxs[i]*slotLen
		copy(blob[off:], ct)
		copy(blob[off+ptLen:], tag[:])
		Wipe(pt)
		Wipe(keys[i][:])
	}
	return blob, nil
}

// DuressOpen opens the slot that password selects.
func DuressOpen(pw, blob []byte, nSlots int, kp KDFParams) ([]byte, error) {
	if nSlots < 2 || nSlots > 8 {
		return nil, ErrParam
	}
	var T uint64
	for b := 0; b < BandCount; b++ {
		if tb := BandTotalSize(b, 0); tb <= uint64(len(blob)) && tb > T {
			T = tb
		}
	}
	if T == 0 || T < 16+rsxdN*(16+6+1) {
		return nil, ErrFormat
	}
	slotLen := int((T - 16) / rsxdN)
	ptLen := slotLen - 16
	K, err := duressDerive(pw, blob[:16], kp)
	if err != nil {
		return nil, err
	}
	idx, ks := duressSlot(K)
	Wipe(K)
	off := 16 + idx*slotLen
	pt, err := AeadDecrypt(ks[:], make([]byte, 12), []byte("RSXD1"), blob[off:off+ptLen], blob[off+ptLen:off+slotLen])
	Wipe(ks[:])
	if err != nil {
		return nil, ErrAuth
	}
	defer Wipe(pt)
	if pt[0] != 1 || pt[1]&^rsxdFilled != 0 {
		return nil, ErrFormat
	}
	plen := int(rd32(pt[2:]))
	if plen > ptLen-6 {
		return nil, ErrFormat
	}
	var acc byte
	for _, b := range pt[6+plen:] {
		acc |= b
	}
	if acc != 0 {
		return nil, ErrFormat
	}
	return append([]byte(nil), pt[6:6+plen]...), nil
}
