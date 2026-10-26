package rsx

// B10 forward-secure ratchet (rsx_ratchet_*).
// K_0 = HKDF(master, salt, "RSX ratchet root"); hdr = HKDF(master, salt, "RSX ratchet hdr")
// mk_i = HKDF(K_i, be64(i), "RSX ratchet msg"); K_{i+1} = HKDF(K_i, be64(i), "RSX ratchet step")
// v2 blob: 0x02 || nonce12 || enc_index8 || ct || tag16

// Ratchet is the forward-secure key state.
type Ratchet struct {
	tip, hdr [32]byte
	index    uint64
	open     bool
}

// NewRatchet creates a ratchet from a 32-byte master and an optional 16-byte salt (nil = zeros).
func NewRatchet(master, salt []byte) (*Ratchet, error) {
	if len(master) != 32 || (salt != nil && len(salt) != 16) {
		return nil, ErrParam
	}
	s := make([]byte, 16)
	copy(s, salt)
	r := &Ratchet{open: true}
	r.tip = hkdf32(master, s, "RSX ratchet root")
	r.hdr = hkdf32(master, s, "RSX ratchet hdr")
	return r, nil
}

// Close wipes the state.
func (r *Ratchet) Close() { Wipe(r.tip[:]); Wipe(r.hdr[:]); r.open = false }

// Index is the next step to use.
func (r *Ratchet) Index() uint64 { return r.index }

// Next emits the current message key and advances the tip.
func (r *Ratchet) Next() ([32]byte, error) {
	var mk [32]byte
	if !r.open {
		return mk, ErrParam
	}
	if r.index == ^uint64(0) {
		return mk, ErrRange
	}
	var ctr [8]byte
	be64(ctr[:], r.index)
	mk = hkdf32(r.tip[:], ctr[:], "RSX ratchet msg")
	next := hkdf32(r.tip[:], ctr[:], "RSX ratchet step")
	r.tip = next
	Wipe(next[:])
	r.index++
	return mk, nil
}

const ratchetHdr = 1 + 12 + 8

func ratchetMask(hdr *[32]byte, nonce []byte) [8]byte {
	var m [8]byte
	ChaCha20(hdr[:], nonce, 0, make([]byte, 8), m[:])
	return m
}

// Seal encrypts the next message; a failed seal never burns a step.
func (r *Ratchet) Seal(aad, pt []byte) ([]byte, error) {
	if !r.open {
		return nil, ErrParam
	}
	tmp := *r
	idx := tmp.index
	mk, err := tmp.Next()
	if err != nil {
		return nil, err
	}
	defer Wipe(mk[:])
	o := make([]byte, ratchetHdr, ratchetHdr+len(pt)+16)
	o[0] = 0x02
	if Random(o[1:13]) != nil {
		return nil, ErrRNG
	}
	m := ratchetMask(&tmp.hdr, o[1:13])
	var be [8]byte
	be64(be[:], idx)
	for i := 0; i < 8; i++ {
		o[13+i] = be[i] ^ m[i]
	}
	a := append(append([]byte("RSXR2"), o[:ratchetHdr]...), aad...)
	ct, tag, _ := AeadEncrypt(mk[:], o[1:13], a, pt)
	o = append(append(o, ct...), tag[:]...)
	*r = tmp
	return o, nil
}

// Open decrypts the next message in sequence; a forged blob never desyncs the state.
func (r *Ratchet) Open(aad, blob []byte) ([]byte, error) {
	if !r.open || len(blob) < ratchetHdr+16 {
		return nil, ErrParam
	}
	if blob[0] != 0x02 {
		return nil, ErrFormat
	}
	m := ratchetMask(&r.hdr, blob[1:13])
	var idx uint64
	for i := 0; i < 8; i++ {
		idx = idx<<8 | uint64(blob[13+i]^m[i])
	}
	if idx != r.index {
		return nil, ErrFormat
	}
	tmp := *r
	mk, err := tmp.Next()
	if err != nil {
		return nil, err
	}
	defer Wipe(mk[:])
	n := len(blob) - ratchetHdr - 16
	a := append(append([]byte("RSXR2"), blob[:ratchetHdr]...), aad...)
	pt, err := AeadDecrypt(mk[:], blob[1:13], a, blob[ratchetHdr:ratchetHdr+n], blob[ratchetHdr+n:])
	if err != nil {
		return nil, ErrAuth
	}
	*r = tmp
	return pt, nil
}
