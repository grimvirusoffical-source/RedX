package rsx

import (
	"encoding/base64"
	"strconv"
	"strings"
)

// PHC string format (https://github.com/P-H-C/phc-string-format) for Argon2id:
//
//	$argon2id$v=19$m=<KiB>,t=<passes>,p=<lanes>$<salt>$<hash>
//
// salt and hash are standard base64 without padding. Parsing is strict: the
// algorithm must be argon2id, v must be 19, m,t,p must appear exactly once in that
// order with canonical decimal values inside the librsx bounds, and no other
// parameters (keyid, data) are accepted.

// PHC is a parsed Argon2id PHC string.
type PHC struct {
	T, M, P uint32
	Salt    []byte
	Hash    []byte
}

const (
	phcMinSalt = 8
	phcMaxSalt = 64
	phcMinHash = 16
	phcMaxHash = 64
)

var phcB64 = base64.RawStdEncoding.Strict()

// Encode returns the PHC string.
func (p PHC) Encode() (string, error) {
	if err := p.check(); err != nil {
		return "", err
	}
	return "$argon2id$v=19$m=" + strconv.FormatUint(uint64(p.M), 10) + ",t=" + strconv.FormatUint(uint64(p.T), 10) +
		",p=" + strconv.FormatUint(uint64(p.P), 10) + "$" + phcB64.EncodeToString(p.Salt) + "$" + phcB64.EncodeToString(p.Hash), nil
}

func (p PHC) check() error {
	if p.T < 1 || p.T > Argon2TMax || p.P < 1 || p.P > Argon2PMax || p.M < 8*p.P || p.M > Argon2MMax {
		return ErrRange
	}
	if len(p.Salt) < phcMinSalt || len(p.Salt) > phcMaxSalt || len(p.Hash) < phcMinHash || len(p.Hash) > phcMaxHash {
		return ErrFormat
	}
	return nil
}

func phcUint(s string) (uint32, bool) {
	if s == "" || len(s) > 10 || (len(s) > 1 && s[0] == '0') {
		return 0, false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return 0, false
		}
	}
	v, err := strconv.ParseUint(s, 10, 32)
	return uint32(v), err == nil
}

// ParsePHC parses a strict Argon2id PHC string.
func ParsePHC(s string) (PHC, error) {
	var p PHC
	if len(s) > 512 {
		return p, ErrFormat
	}
	f := strings.Split(s, "$")
	if len(f) != 6 || f[0] != "" || f[1] != "argon2id" || f[2] != "v=19" {
		return p, ErrFormat
	}
	kv := strings.Split(f[3], ",")
	if len(kv) != 3 {
		return p, ErrFormat
	}
	names := []string{"m=", "t=", "p="}
	vals := make([]uint32, 3)
	for i, x := range kv {
		if !strings.HasPrefix(x, names[i]) {
			return p, ErrFormat
		}
		v, ok := phcUint(x[2:])
		if !ok {
			return p, ErrFormat
		}
		vals[i] = v
	}
	p.M, p.T, p.P = vals[0], vals[1], vals[2]
	var err error
	if p.Salt, err = phcB64.DecodeString(f[4]); err != nil {
		return PHC{}, ErrFormat
	}
	if p.Hash, err = phcB64.DecodeString(f[5]); err != nil {
		return PHC{}, ErrFormat
	}
	if err := p.check(); err != nil {
		return PHC{}, err
	}
	return p, nil
}

// HashPasswordPHC derives an Argon2id hash with a fresh 16-byte salt and returns the PHC string.
func HashPasswordPHC(pw []byte, t, mKiB, p uint32) (string, error) {
	salt := make([]byte, 16)
	if err := Random(salt); err != nil {
		return "", err
	}
	h, err := Argon2id(pw, salt, t, mKiB, p, 32)
	if err != nil {
		return "", err
	}
	defer Wipe(h)
	return PHC{T: t, M: mKiB, P: p, Salt: salt, Hash: h}.Encode()
}

// VerifyPasswordPHC recomputes the hash with the stored parameters and compares in constant time.
func VerifyPasswordPHC(pw []byte, phc string) (bool, error) {
	p, err := ParsePHC(phc)
	if err != nil {
		return false, err
	}
	h, err := Argon2id(pw, p.Salt, p.T, p.M, p.P, len(p.Hash))
	if err != nil {
		return false, err
	}
	defer Wipe(h)
	return CtEq(h, p.Hash), nil
}
