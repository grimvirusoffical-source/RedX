package rsx

import "runtime"

// Wipe zeroes b. The KeepAlive keeps the stores from being optimised away.
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func wipe32(w []uint32) {
	for i := range w {
		w[i] = 0
	}
	runtime.KeepAlive(w)
}

func wipe64(w []uint64) {
	for i := range w {
		w[i] = 0
	}
	runtime.KeepAlive(w)
}

// CtEq reports whether a and b are equal, in time that depends only on their lengths.
// Slices of different lengths are never equal.
func CtEq(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	var r byte
	for i := range a {
		r |= a[i] ^ b[i]
	}
	return ctIsZero8(r) == 1
}

// ctIsZero8 returns 1 if x == 0 else 0, without branching.
func ctIsZero8(x byte) int {
	v := uint32(x)
	return int(((v - 1) >> 31) & 1)
}

func be16(b []byte, v uint16) { b[0], b[1] = byte(v>>8), byte(v) }
func be24(b []byte, v uint32) { b[0], b[1], b[2] = byte(v>>16), byte(v>>8), byte(v) }
func be32(b []byte, v uint32) { b[0], b[1], b[2], b[3] = byte(v>>24), byte(v>>16), byte(v>>8), byte(v) }
func be64(b []byte, v uint64) {
	for i := 7; i >= 0; i-- {
		b[i] = byte(v)
		v >>= 8
	}
}
func rd16(b []byte) uint16 { return uint16(b[0])<<8 | uint16(b[1]) }
func rd24(b []byte) uint32 { return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]) }
func rd32(b []byte) uint32 {
	return uint32(b[0])<<24 | uint32(b[1])<<16 | uint32(b[2])<<8 | uint32(b[3])
}
func rd64(b []byte) uint64 {
	var v uint64
	for i := 0; i < 8; i++ {
		v = v<<8 | uint64(b[i])
	}
	return v
}
func le32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}
func putLe32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}
func le64(b []byte) uint64       { return uint64(le32(b)) | uint64(le32(b[4:]))<<32 }
func putLe64(b []byte, v uint64) { putLe32(b, uint32(v)); putLe32(b[4:], uint32(v>>32)) }
