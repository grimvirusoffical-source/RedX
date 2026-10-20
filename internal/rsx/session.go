package rsx

import (
	"io"
	"os"
	"path/filepath"
)

// Session warnings (RSX_WARN_*).
const (
	WarnRollback     uint32 = 0x1
	WarnNoGenRecord  uint32 = 0x2
	WarnGenRecordBad uint32 = 0x4
	WarnLegacyKeymap uint32 = 0x8
	WarnNoPin        uint32 = 0x10
	WarnHWBound      uint32 = 0x20
	WarnNoDumpGuard  uint32 = 0x100
)

// KDFParams are the Argon2id parameters used when a keymap is written.
type KDFParams struct{ T, M, P uint32 }

// DefaultKDF is librsx's default (t=3, m=256 MiB, p=4).
var DefaultKDF = KDFParams{Argon2TDefault, Argon2MDefault, Argon2PDefault}

// Session holds an unlocked port master key (KEK). Close wipes it.
type Session struct {
	kek  [32]byte
	gen  uint64
	open bool
	kdf  KDFParams
}

// NewSessionFromKey wraps a 32-byte KEK that the host manages itself (no keymap file).
// Data sealed with it is the same RSX3/RSXC as with a keymap session.
func NewSessionFromKey(kek []byte) (*Session, error) {
	if len(kek) != 32 {
		return nil, ErrParam
	}
	s := &Session{open: true, kdf: DefaultKDF}
	copy(s.kek[:], kek)
	return s, nil
}

// Close wipes the key.
func (s *Session) Close() {
	if s == nil {
		return
	}
	Wipe(s.kek[:])
	s.open = false
}

// Generation is the keymap generation as unlocked (0 for keys without a keymap).
func (s *Session) Generation() uint64 { return s.gen }

func (s *Session) ok() error {
	if s == nil || !s.open {
		return ErrParam
	}
	return nil
}

const (
	kxai3Len   = 95
	kxai4Len   = 96
	kxaiFlagHW = 0x01
)

func mixHW(wk []byte, hw []byte) {
	ikm := append(append([]byte(nil), wk...), hw...)
	o, _ := HkdfSha256(ikm, nil, []byte("KXAI hw v1"), 32)
	copy(wk, o)
	Wipe(ikm)
	Wipe(o)
}

func writeKXAI(path string, pw, kek []byte, kp KDFParams, gen uint64, hw []byte) error {
	n := kxai3Len
	if hw != nil {
		n = kxai4Len
	}
	f := make([]byte, 96)
	if Random(f[19:35]) != nil || Random(f[35:47]) != nil {
		return ErrRNG
	}
	wk, err := Argon2id(pw, f[19:35], kp.T, kp.M, kp.P, 32)
	if err != nil {
		if err == ErrRange {
			return ErrRange
		}
		return ErrParam
	}
	defer Wipe(wk)
	if hw != nil {
		mixHW(wk, hw)
	}
	copy(f, "KXAI")
	f[4] = 3
	if hw != nil {
		f[4] = 4
	}
	f[5], f[6] = byte(kp.T), byte(kp.P)
	be32(f[7:], kp.M)
	be64(f[11:], gen)
	var ct []byte
	var tag [16]byte
	if hw != nil {
		f[47] = kxaiFlagHW
		ct, tag, _ = AeadEncrypt(wk, f[35:47], f[:48], kek)
		copy(f[48:], ct)
		copy(f[80:], tag[:])
	} else {
		ct, tag, _ = AeadEncrypt(wk, f[35:47], f[:35], kek)
		copy(f[47:], ct)
		copy(f[79:], tag[:])
	}
	Wipe(ct)
	return atomicWrite(path, f[:n])
}

// readKXAI parses and unlocks KXAI v1..v4.
func readKXAI(path string, pw []byte, hw []byte) (kek [32]byte, gen uint64, ver int, err error) {
	b, e := os.ReadFile(path)
	if e != nil {
		return kek, 0, 0, ErrIO
	}
	return parseKXAI(b, pw, hw)
}

func parseKXAI(f, pw, hw []byte) (kek [32]byte, gen uint64, ver int, err error) {
	if len(f) < 11 || string(f[:4]) != "KXAI" {
		return kek, 0, 0, ErrFormat
	}
	ver = int(f[4])
	t, p, m := uint32(f[5]), uint32(f[6]), rd32(f[7:])
	want := map[int]int{4: kxai4Len, 3: kxai3Len, 2: 87, 1: 75}[ver]
	if want == 0 || len(f) != want {
		return kek, 0, 0, ErrFormat
	}
	so := 11
	if ver >= 3 {
		so = 19
	}
	salt := f[so : so+16]
	wk, e := Argon2id(pw, salt, t, m, p, 32)
	if e != nil {
		if e == ErrRange {
			return kek, 0, 0, ErrRange
		}
		return kek, 0, 0, ErrParam
	}
	defer Wipe(wk)
	var pt []byte
	switch ver {
	case 1:
		pt, e = AeadDecrypt(wk, salt[:12], []byte("KXAI1"), f[27:59], f[59:75])
	case 2:
		pt, e = AeadDecrypt(wk, f[27:39], f[:27], f[39:71], f[71:87])
	case 3:
		pt, e = AeadDecrypt(wk, f[35:47], f[:35], f[47:79], f[79:95])
		gen = rd64(f[11:])
	case 4:
		if f[47]&kxaiFlagHW == 0 {
			return kek, 0, 0, ErrFormat
		}
		if hw == nil {
			return kek, 0, 0, ErrHW
		}
		mixHW(wk, hw)
		pt, e = AeadDecrypt(wk, f[35:47], f[:48], f[48:80], f[80:96])
		gen = rd64(f[11:])
	}
	if e != nil {
		return kek, 0, 0, ErrAuth
	}
	copy(kek[:], pt)
	Wipe(pt)
	return kek, gen, ver, nil
}

func genMAC(kek []byte, rec []byte) []byte {
	m := HmacSha256(kek, append([]byte("RSX keymap gen"), rec[:13]...))
	return m[:16]
}

// readRec: 0 ok, 1 missing, 2 bad.
func readRec(path string, kek []byte) (uint64, int) {
	r, err := os.ReadFile(path)
	if err != nil {
		return 0, 1
	}
	if len(r) != 29 || string(r[:4]) != "KXGN" || r[4] != 1 || !CtEq(genMAC(kek, r), r[13:29]) {
		return 0, 2
	}
	return rd64(r[5:]), 0
}

func writeRec(path string, kek []byte, gen uint64) error {
	r := make([]byte, 29)
	copy(r, "KXGN")
	r[4] = 1
	be64(r[5:], gen)
	copy(r[13:], genMAC(kek, r))
	return atomicWrite(path, r)
}

func resolveKeymap(path string) string {
	fi, err := os.Stat(path)
	if err != nil || !fi.IsDir() {
		return path
	}
	a := filepath.Join(path, "session.kxai")
	b := filepath.Join(path, "keymap.rsx")
	for _, c := range []string{a, b} {
		if f, err := os.Open(c); err == nil {
			m := make([]byte, 4)
			_, rerr := io.ReadFull(f, m)
			f.Close()
			if rerr == nil && string(m) == "KXAI" {
				return c
			}
		}
	}
	return a
}

// SessionOptions controls OpenSession.
type SessionOptions struct {
	MinGen   uint64     // host-pinned generation (0 = none)
	ReadOnly bool       // never create or write anything
	HWToken  []byte     // 32-byte machine token: creates/opens a hardware-bound KXAI v4
	KDF      *KDFParams // parameters for a newly written keymap (default DefaultKDF)
}

// OpenSession unlocks (or, if missing and not read-only, creates) the keymap at path.
func OpenSession(pw []byte, path string, o *SessionOptions) (*Session, uint32, error) {
	if o == nil {
		o = &SessionOptions{}
	}
	if o.HWToken != nil && len(o.HWToken) != 32 {
		return nil, 0, ErrParam
	}
	kp := DefaultKDF
	if o.KDF != nil {
		kp = *o.KDF
	}
	path = resolveKeymap(path)
	s := &Session{kdf: kp}
	var w uint32 = WarnNoDumpGuard // Go cannot pin or exclude heap memory from core dumps
	if _, err := os.Lstat(path); err != nil {
		if !os.IsNotExist(err) {
			return nil, 0, ErrIO
		}
		if o.ReadOnly {
			return nil, 0, ErrIO
		}
		if Random(s.kek[:]) != nil {
			return nil, 0, ErrRNG
		}
		s.gen = 1
		err := writeKXAI(path, pw, s.kek[:], kp, s.gen, o.HWToken)
		if err == nil {
			err = writeRec(path+".gen", s.kek[:], s.gen)
		}
		if err != nil {
			os.Remove(path)
			s.Close()
			return nil, 0, err
		}
	} else {
		kek, gen, ver, err := readKXAI(path, pw, o.HWToken)
		if err != nil {
			return nil, 0, err
		}
		s.kek, s.gen = kek, gen
		if ver < 3 {
			w |= WarnLegacyKeymap
		}
		if ver == 4 {
			w |= WarnHWBound
		}
		rec, gr := readRec(path+".gen", s.kek[:])
		switch {
		case gr == 1:
			w |= WarnNoGenRecord
		case gr == 2:
			w |= WarnGenRecordBad
		case s.gen < rec:
			w |= WarnRollback
		}
		if s.gen < o.MinGen {
			w |= WarnRollback
		}
		if !o.ReadOnly && (gr != 0 || rec < s.gen) {
			writeRec(path+".gen", s.kek[:], s.gen)
		}
	}
	s.open = true
	return s, w, nil
}

// OpenSessionPinned is rsx_session_open_pinned: a host-held generation pin at pinPath.
func OpenSessionPinned(pw []byte, path, pinPath string, o *SessionOptions) (*Session, uint32, error) {
	s, w, err := OpenSession(pw, path, o)
	if err != nil {
		return nil, 0, err
	}
	pin, pr := readRec(pinPath, s.kek[:])
	switch {
	case pr == 1:
		w |= WarnNoPin
	case pr == 2:
		w |= WarnGenRecordBad
	case s.gen < pin:
		w |= WarnRollback
	}
	if pr != 0 || pin < s.gen {
		writeRec(pinPath, s.kek[:], s.gen)
	}
	return s, w, nil
}

// PinUpdate raises (never lowers) the host pin to the current generation.
func (s *Session) PinUpdate(pinPath string) error {
	if err := s.ok(); err != nil {
		return err
	}
	if pin, pr := readRec(pinPath, s.kek[:]); pr == 0 && pin >= s.gen {
		return nil
	}
	return writeRec(pinPath, s.kek[:], s.gen)
}

// ChangePassword rewraps the KEK under newPW (fresh salt and nonce, generation +1).
func (s *Session) ChangePassword(newPW []byte, path string) error {
	if err := s.ok(); err != nil {
		return err
	}
	if s.gen == ^uint64(0) {
		return ErrRange
	}
	path = resolveKeymap(path)
	next := s.gen + 1
	if rec, gr := readRec(path+".gen", s.kek[:]); gr == 0 && rec >= next {
		next = rec + 1
	}
	if err := writeKXAI(path, newPW, s.kek[:], s.kdf, next, nil); err != nil {
		return err
	}
	s.gen = next
	return writeRec(path+".gen", s.kek[:], next)
}

// BackupKeymap writes a standalone KXAI holding the same KEK under backupPW. It never overwrites.
func (s *Session) BackupKeymap(backupPW []byte, backupPath string) error {
	if err := s.ok(); err != nil {
		return err
	}
	if _, err := os.Lstat(backupPath); err == nil {
		return ErrIO
	}
	return writeKXAI(backupPath, backupPW, s.kek[:], s.kdf, s.gen, nil)
}

// VerifyBackup unlocks a backup read-only and checks it holds this session's KEK.
func (s *Session) VerifyBackup(backupPW []byte, backupPath string) (uint64, error) {
	if err := s.ok(); err != nil {
		return 0, err
	}
	kek, g, _, err := readKXAI(backupPath, backupPW, nil)
	if err != nil {
		return 0, err
	}
	defer Wipe(kek[:])
	if !CtEq(kek[:], s.kek[:]) {
		return g, ErrMismatch
	}
	return g, nil
}

func restoreWithKEK(kek []byte, g uint64, newPW []byte, path string, kp KDFParams) error {
	path = resolveKeymap(path)
	if rec, gr := readRec(path+".gen", kek); gr == 0 && rec > g {
		g = rec
	}
	if lk, lg, _, err := readKXAI(path, newPW, nil); err == nil && CtEq(lk[:], kek) && lg > g {
		g = lg
	}
	if g == ^uint64(0) {
		return ErrRange
	}
	if err := writeKXAI(path, newPW, kek, kp, g+1, nil); err != nil {
		return err
	}
	return writeRec(path+".gen", kek, g+1)
}

// RestoreKeymap writes the backup's KEK as the live keymap under newPW (generation = max+1).
func RestoreKeymap(backupPW []byte, backupPath string, newPW []byte, keymapPath string, kp *KDFParams) error {
	kek, g, _, err := readKXAI(backupPath, backupPW, nil)
	if err != nil {
		return err
	}
	defer Wipe(kek[:])
	p := DefaultKDF
	if kp != nil {
		p = *kp
	}
	return restoreWithKEK(kek[:], g, newPW, keymapPath, p)
}

// Split splits the KEK into k-of-n RSXS share cards (65 bytes each).
func (s *Session) Split(k, n int) ([][]byte, error) {
	if err := s.ok(); err != nil {
		return nil, err
	}
	return ShamirSplit(s.kek[:], k, n)
}

// RestoreKeymapShares rebuilds the keymap from share cards under newPW.
func RestoreKeymapShares(shares [][]byte, newPW []byte, keymapPath string, kp *KDFParams) error {
	sec, err := ShamirCombine(shares)
	if err != nil {
		return err
	}
	defer Wipe(sec)
	if len(sec) != 32 {
		return ErrFormat
	}
	p := DefaultKDF
	if kp != nil {
		p = *kp
	}
	return restoreWithKEK(sec, 0, newPW, keymapPath, p)
}
