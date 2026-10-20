package host

import (
	"bufio"
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/crypto/argon2"

	"redx/engine/sec"
)

// Backup archive encryption.
//
// Everything that touches the cipher goes through BackupSealer so the
// algorithm can later be swapped for Red-SecretsXAI (librsx) without changing
// the archive code. Today the implementation reuses the repository's own
// engine/sec stream format (HKDF-SHA256 key wrap + authenticated segments)
// with an Argon2id passphrase KDF.
//
// File layout:
//
//	"RXBK1\n" | header JSON line ("\n"-terminated) | engine/sec stream of the tar.gz
//
// The magic and header line are bound into the stream as additional
// authenticated data, so the KDF parameters and mode cannot be altered.
// Legacy backups are plain tar.gz (gzip magic 1f 8b) and are still restorable
// with a warning.

const backupMagic = "RXBK1\n"

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
	backupCipher    = "redx-sec-v1"
	backupKeyID     = "redx-backup"
	backupKeyFile   = "backup.key"
)

type secSealer struct {
	key  []byte
	hdr  BackupHeader
	line []byte
}

func keyFP(k []byte) string { s := sha256.Sum256(k); return hex.EncodeToString(s[:8]) }

// NewBackupSealer picks passphrase mode when a passphrase is given, otherwise hostkey mode.
func NewBackupSealer(k BackupKeys) (BackupSealer, error) {
	h := BackupHeader{V: 1, Cipher: backupCipher}
	var key []byte
	switch {
	case k.Passphrase != "":
		salt := make([]byte, 16)
		if _, err := rand.Read(salt); err != nil {
			return nil, err
		}
		h.Mode, h.KDF, h.T, h.M, h.P = "passphrase", "argon2id", backupKDFTime, backupKDFMemKiB, backupKDFPar
		h.Salt = base64.RawStdEncoding.EncodeToString(salt)
		key = argon2.IDKey([]byte(k.Passphrase), salt, h.T, h.M, h.P, 32)
	case len(k.HostKey) == 32:
		h.Mode, h.KeyFP = "hostkey", keyFP(k.HostKey)
		key = append([]byte(nil), k.HostKey...)
	default:
		return nil, errors.New("backup: no passphrase and no backup key")
	}
	line, _ := json.Marshal(h)
	return &secSealer{key: key, hdr: h, line: append(line, '\n')}, nil
}

func (s *secSealer) aad(line []byte) []byte { return append([]byte(backupMagic), line...) }

type sealWriter struct {
	pw   *io.PipeWriter
	done chan error
}

func (w *sealWriter) Write(p []byte) (int, error) { return w.pw.Write(p) }
func (w *sealWriter) Close() error {
	_ = w.pw.Close()
	return <-w.done
}

func (s *secSealer) Seal(dst io.Writer) (io.WriteCloser, error) {
	mk, err := sec.NewMasterKey(backupKeyID, s.key)
	if err != nil {
		return nil, err
	}
	if _, err := io.WriteString(dst, backupMagic); err != nil {
		return nil, err
	}
	if _, err := dst.Write(s.line); err != nil {
		return nil, err
	}
	pr, pw := io.Pipe()
	w := &sealWriter{pw: pw, done: make(chan error, 1)}
	go func() {
		err := sec.Encrypt(dst, pr, mk, sec.Options{Context: s.aad(s.line)})
		mk.Destroy()
		_ = pr.CloseWithError(err)
		w.done <- err
	}()
	return w, nil
}

func (s *secSealer) Open(src io.Reader, hdr BackupHeader, raw []byte) (io.Reader, error) {
	mk, err := sec.NewMasterKey(backupKeyID, s.key)
	if err != nil {
		return nil, err
	}
	ring, err := sec.NewKeyring(mk)
	if err != nil {
		return nil, err
	}
	r, err := sec.NewReader(src, ring, sec.Options{Context: s.aad(raw)})
	if err != nil {
		if errors.Is(err, sec.ErrAuth) {
			return nil, errors.New("backup: wrong passphrase or backup key, or the archive was changed")
		}
		return nil, err
	}
	return r, nil
}

// openerFor derives the key for an existing header.
func openerFor(h BackupHeader, k BackupKeys) (BackupSealer, error) {
	if h.V != 1 || h.Cipher != backupCipher {
		return nil, fmt.Errorf("backup: unsupported encrypted backup (v%d, %s); it was made by a newer RedX", h.V, h.Cipher)
	}
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
		return &secSealer{key: argon2.IDKey([]byte(k.Passphrase), salt, h.T, h.M, h.P, 32), hdr: h}, nil
	case "hostkey":
		if len(k.HostKey) != 32 {
			return nil, fmt.Errorf("backup is encrypted with host backup key %s: pass --backup-key-file (the %s from the source host)", h.KeyFP, backupKeyFile)
		}
		if keyFP(k.HostKey) != h.KeyFP {
			return nil, fmt.Errorf("backup was encrypted with backup key %s, but the given key is %s", h.KeyFP, keyFP(k.HostKey))
		}
		return &secSealer{key: append([]byte(nil), k.HostKey...), hdr: h}, nil
	}
	return nil, fmt.Errorf("backup: unknown mode %q", h.Mode)
}

// OpenBackup detects the archive format. It returns the plaintext tar.gz
// reader, the header (nil for a legacy plaintext archive) and an error.
func OpenBackup(src io.Reader, k BackupKeys) (io.Reader, *BackupHeader, error) {
	br := bufio.NewReader(src)
	peek, err := br.Peek(len(backupMagic))
	if err != nil && len(peek) < 2 {
		return nil, nil, fmt.Errorf("backup: %w", err)
	}
	if len(peek) >= 2 && peek[0] == 0x1f && peek[1] == 0x8b {
		return br, nil, nil // legacy plaintext tar.gz
	}
	if string(peek) != backupMagic {
		return nil, nil, errors.New("backup: not a RedX backup (unknown format)")
	}
	_, _ = br.Discard(len(backupMagic))
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
	s, err := openerFor(h, k)
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
	k := make([]byte, 32)
	if _, err := rand.Read(k); err != nil {
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
