package host

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"redx/internal/rsx"
)

// Backup archive encryption.
//
// Everything that touches the cipher goes through BackupSealer. Since
// 2026-10-20 new backups are Red-SecretsXAI RSX3 v2 streams:
//
//	"RXBK2\n" | header JSON line ("\n"-terminated) | RSX3 stream of the tar.gz
//
// The RSX3 key-encryption key is Argon2id(passphrase, salt) in passphrase mode,
// or the 32-byte host backup key in hostkey mode; RSX3 wraps a fresh random data
// key under it. The magic and header line are the RSX3 additional data, so the
// KDF parameters and mode cannot be altered, and RSX3 authenticates completion
// (a truncated archive never restores).
//
// Older archives are refused, never decrypted or unpacked: "RXBK1\n" (AES-GCM
// era) and plain tar.gz (gzip magic 1f 8b) both fail with ErrLegacyBackup.

const (
	backupMagic   = "RXBK2\n"
	backupMagicV1 = "RXBK1\n" // refused
)

// ErrLegacyBackup is returned for .tgz and RXBK1 (AES-era) archives.
var ErrLegacyBackup = errors.New("unsupported legacy backup format; create a new backup with this version")

// BackupSealer encrypts and decrypts one backup archive stream.
type BackupSealer interface {
	// Seal returns a writer: plaintext written to it is encrypted to dst. Close finishes the stream.
	Seal(dst io.Writer) (io.WriteCloser, error)
	// Open returns the plaintext reader for an archive whose magic and header were already read.
	Open(src io.Reader, hdr BackupHeader, rawHeader []byte) (io.Reader, error)
}

// BackupHeader is the plaintext header of an encrypted backup. It holds no secret.
type BackupHeader struct {
	V      int    `json:"v"`
	Mode   string `json:"mode"` // "passphrase" or "hostkey"
	KDF    string `json:"kdf,omitempty"`
	T      uint32 `json:"t,omitempty"`
	M      uint32 `json:"m_kib,omitempty"`
	P      uint8  `json:"p,omitempty"`
	Salt   string `json:"salt,omitempty"`
	KeyFP  string `json:"key_fp,omitempty"` // hostkey mode: sha256 fingerprint prefix of the key
	Cipher string `json:"cipher"`
}

// BackupKeys is what a caller can offer to seal or open a backup.
type BackupKeys struct {
	Passphrase string // preferred: an operator passphrase
	HostKey    []byte // fallback: 32 random bytes kept outside the archive
}

const (
	backupKDFTime   = 3
	backupKDFMemKiB = 64 * 1024
	backupKDFPar    = 4
	backupCipher    = "rsx3-v2"

	backupKeyID   = "redx-backup"
	backupKeyFile = "backup.key"
)

type rsxSealer struct {
	key  []byte
	hdr  BackupHeader
	line []byte
}

func keyFP(k []byte) string { s := rsx.Sha256(k); return hex.EncodeToString(s[:8]) }

func backupKDF(pass string, salt []byte, t, m uint32, p uint8) ([]byte, error) {
	return rsx.Argon2id([]byte(pass), salt, t, m, uint32(p), 32)
}

// NewBackupSealer picks passphrase mode when a passphrase is given, otherwise hostkey mode.
func NewBackupSealer(k BackupKeys) (BackupSealer, error) {
	h := BackupHeader{V: 2, Cipher: backupCipher}
	var key []byte
	switch {
	case k.Passphrase != "":
		salt, err := rsx.RandomBytes(16)
		if err != nil {
			return nil, err
		}
		h.Mode, h.KDF, h.T, h.M, h.P = "passphrase", "argon2id", backupKDFTime, backupKDFMemKiB, backupKDFPar
		h.Salt = base64.RawStdEncoding.EncodeToString(salt)
		if key, err = backupKDF(k.Passphrase, salt, h.T, h.M, h.P); err != nil {
			return nil, err
		}
	case len(k.HostKey) == 32:
		h.Mode, h.KeyFP = "hostkey", keyFP(k.HostKey)
		key = append([]byte(nil), k.HostKey...)
	default:
		return nil, errors.New("backup: no passphrase and no backup key")
	}
	line, _ := json.Marshal(h)
	return &rsxSealer{key: key, hdr: h, line: append(line, '\n')}, nil
}

func backupAAD(magic string, line []byte) []byte { return append([]byte(magic), line...) }

type rsxWriter struct {
	w *rsx.StreamWriter
	s *rsx.Session
}

func (w *rsxWriter) Write(p []byte) (int, error) { return w.w.Write(p) }
func (w *rsxWriter) Close() error {
	err := w.w.Close()
	w.s.Close()
	return err
}

func (s *rsxSealer) Seal(dst io.Writer) (io.WriteCloser, error) {
	if s.line == nil {
		return nil, errors.New("backup: this sealer only opens archives")
	}
	sess, err := rsx.NewSessionFromKey(s.key)
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(dst, backupMagic); err != nil {
		sess.Close()
		return nil, err
	}
	if _, err := dst.Write(s.line); err != nil {
		sess.Close()
		return nil, err
	}
	w, err := sess.NewEncryptWriter(dst, backupAAD(backupMagic, s.line))
	if err != nil {
		sess.Close()
		return nil, err
	}
	return &rsxWriter{w: w, s: sess}, nil
}

var errBackupAuth = errors.New("backup: wrong passphrase or backup key, or the archive was changed")

func (s *rsxSealer) Open(src io.Reader, hdr BackupHeader, raw []byte) (io.Reader, error) {
	sess, err := rsx.NewSessionFromKey(s.key)
	if err != nil {
		return nil, err
	}
	r, err := sess.NewDecryptReader(src, backupAAD(backupMagic, raw))
	if err != nil {
		sess.Close()
		if errors.Is(err, rsx.ErrAuth) {
			return nil, errBackupAuth
		}
		return nil, fmt.Errorf("backup: %v", err)
	}
	return &rsxReader{r: r, s: sess}, nil
}

// rsxReader maps RSX3 errors to backup errors and closes the session at the end.
type rsxReader struct {
	r *rsx.StreamReader
	s *rsx.Session
}

func (r *rsxReader) Read(p []byte) (int, error) {
	n, err := r.r.Read(p)
	if err != nil {
		r.s.Close()
		if err != io.EOF {
			if errors.Is(err, rsx.ErrAuth) {
				return n, errBackupAuth
			}
			return n, fmt.Errorf("backup: archive is truncated or damaged (%v)", err)
		}
	}
	return n, err
}

// openerFor derives the key for an existing header. magic is the archive's magic line.
func openerFor(magic string, h BackupHeader, k BackupKeys) (BackupSealer, error) {
	if magic != backupMagic || h.V != 2 || h.Cipher != backupCipher {
		return nil, fmt.Errorf("backup: unsupported encrypted backup (v%d, %s); it was made by a newer RedX", h.V, h.Cipher)
	}
	mk := func(key []byte) BackupSealer { return &rsxSealer{key: key, hdr: h} }
	switch h.Mode {
	case "passphrase":
		if k.Passphrase == "" {
			return nil, errors.New("backup is passphrase-encrypted: set REDX_BACKUP_PASSPHRASE or pass --passphrase-file")
		}
		if h.KDF != "argon2id" || h.T == 0 || h.T > 64 || h.M < 8 || h.M > 4<<20 || h.P == 0 {
			return nil, errors.New("backup: bad KDF parameters in header")
		}
		salt, err := base64.RawStdEncoding.DecodeString(h.Salt)
		if err != nil || len(salt) < 16 {
			return nil, errors.New("backup: bad salt in header")
		}
		key, err := backupKDF(k.Passphrase, salt, h.T, h.M, h.P)
		if err != nil {
			return nil, fmt.Errorf("backup: KDF: %v", err)
		}
		return mk(key), nil
	case "hostkey":
		if len(k.HostKey) != 32 {
			return nil, fmt.Errorf("backup is encrypted with host backup key %s: pass --backup-key-file (the %s from the source host)", h.KeyFP, backupKeyFile)
		}
		if keyFP(k.HostKey) != h.KeyFP {
			return nil, fmt.Errorf("backup was encrypted with backup key %s, but the given key is %s", h.KeyFP, keyFP(k.HostKey))
		}
		return mk(append([]byte(nil), k.HostKey...)), nil
	}
	return nil, fmt.Errorf("backup: unknown mode %q", h.Mode)
}

// OpenBackup detects the archive format. It returns the plaintext tar.gz
// reader, the header and an error. Legacy archives (plain tar.gz, RXBK1) are
// refused with ErrLegacyBackup before anything is decrypted or unpacked.
func OpenBackup(src io.Reader, k BackupKeys) (io.Reader, *BackupHeader, error) {
	br := bufio.NewReader(src)
	peek, err := br.Peek(len(backupMagic))
	if err != nil && len(peek) < 2 {
		return nil, nil, fmt.Errorf("backup: %w", err)
	}
	if len(peek) >= 2 && peek[0] == 0x1f && peek[1] == 0x8b {
		return nil, nil, fmt.Errorf("backup: %w (plain .tgz)", ErrLegacyBackup)
	}
	magic := string(peek)
	if magic == backupMagicV1 {
		return nil, nil, fmt.Errorf("backup: %w (RXBK1)", ErrLegacyBackup)
	}
	if magic != backupMagic {
		return nil, nil, errors.New("backup: not a RedX backup (unknown format)")
	}
	_, _ = br.Discard(len(magic))
	raw, err := br.ReadSlice('\n')
	if err != nil {
		return nil, nil, errors.New("backup: truncated header")
	}
	raw = append([]byte(nil), raw...)
	var h BackupHeader
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&h); err != nil {
		return nil, nil, fmt.Errorf("backup: bad header: %v", err)
	}
	s, err := openerFor(magic, h, k)
	if err != nil {
		return nil, &h, err
	}
	r, err := s.Open(br, h, raw)
	return r, &h, err
}

// loadOrCreateBackupKey returns <data>/backup.key, creating 32 random bytes (0600) on first use.
func loadOrCreateBackupKey(dataDir string) ([]byte, error) {
	p := filepath.Join(dataDir, backupKeyFile)
	if b, err := os.ReadFile(p); err == nil {
		if len(b) != 32 {
			return nil, fmt.Errorf("%s: must be 32 bytes", p)
		}
		return b, nil
	}
	k, err := rsx.RandomBytes(32)
	if err != nil {
		return nil, err
	}
	if err := atomicWrite(p, k); err != nil {
		return nil, err
	}
	_ = os.Chmod(p, 0o600)
	return k, nil
}

// ReadBackupKeyFile reads a backup key file: 32 raw bytes or 64 hex characters.
func ReadBackupKeyFile(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	if len(b) == 32 {
		return b, nil
	}
	if d, err := hex.DecodeString(strings.TrimSpace(string(b))); err == nil && len(d) == 32 {
		return d, nil
	}
	return nil, fmt.Errorf("%s: a backup key is 32 bytes (raw or hex)", path)
}
