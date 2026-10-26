package rsx

import "fmt"

// Error is a librsx error code (RSX_E_*).
type Error int

const (
	ErrAuth        Error = -1
	ErrFormat      Error = -2
	ErrParam       Error = -3
	ErrNoMem       Error = -4
	ErrIO          Error = -5
	ErrRange       Error = -6
	ErrRNG         Error = -7
	ErrLimit       Error = -8
	ErrCancelled   Error = -9
	ErrMismatch    Error = -10
	ErrExists      Error = -12
	ErrDowngrade   Error = -13
	ErrHW          Error = -14
	ErrUnsupported Error = -15
	ErrInternal    Error = -99
)

var errNames = map[Error]string{
	ErrAuth: "authentication failed", ErrFormat: "malformed or unsupported", ErrParam: "bad argument",
	ErrNoMem: "out of memory", ErrIO: "I/O error", ErrRange: "out of range", ErrRNG: "random source failed",
	ErrLimit: "resource limit", ErrCancelled: "cancelled", ErrMismatch: "backup holds a different key",
	ErrExists: "output already exists", ErrDowngrade: "container lacks required capabilities",
	ErrHW: "hardware-bound keymap needs a machine token", ErrUnsupported: "unsupported", ErrInternal: "internal error",
}

func (e Error) Error() string {
	if s, ok := errNames[e]; ok {
		return "rsx: " + s
	}
	return fmt.Sprintf("rsx: error %d", int(e))
}

// Code returns the numeric RSX_E_* value.
func (e Error) Code() int { return int(e) }

// Limits shared with rsx.h.
const (
	KeyLen         = 32
	ChunkSize      = 64 * 1024
	MaxAADLen      = 65535
	MaxBlob        = 4 << 30
	MaxChunks      = 1 << 24
	Argon2MDefault = 256 * 1024
	Argon2TDefault = 3
	Argon2PDefault = 4
	Argon2MMax     = 2 * 1024 * 1024
	Argon2MAccept  = 1024 * 1024
	Argon2TMax     = 10
	Argon2PMax     = 16
)
