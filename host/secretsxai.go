package host

import (
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode/utf8"

	"redx/box"
	"redx/internal/rsx"
)

// Red-SecretsXAI password seals for new record text.
//
// Seal and open run on bytes the caller just supplied. They do not walk the
// data directory, do not open pack files, and do not re-wrap, migrate, or
// replace any existing ciphertext.

const (
	secretsFormat = "red-xai-encrypt/rsxc1"
	secretsPin    = "77f81c9abc5e09fb4015ebc5b8a752c31ea190e2"
	secretsEngine = "red-secretsxai"

	maxSecretsPlain = 1 << 20
	maxSecretsBody  = 4 << 20
	secretsFailMax  = 8
)

// SecretsKDFCost is an Argon2id cost (memory in KiB). It is not a TOML field.
// Tests set Config.SecretsKDFOverride. Production leaves the override nil and
// uses secrets_kdf (interactive or librsx) for new seals only.
type SecretsKDFCost struct {
	T, MKiB, P uint32
}

type secretsError struct {
	status int
	msg    string
}

func (e *secretsError) Error() string { return e.msg }

func se(status int, msg string) error { return &secretsError{status: status, msg: msg} }

func (h *Host) secretsKDF() (rsx.KDFParams, string) {
	if h != nil && h.Cfg.SecretsKDFOverride != nil {
		o := h.Cfg.SecretsKDFOverride
		return rsx.KDFParams{T: o.T, M: o.MKiB, P: o.P}, "override"
	}
	if h != nil && h.Cfg.SecretsKDF == "librsx" {
		return rsx.KDFParams{T: rsx.Argon2TDefault, M: rsx.Argon2MDefault, P: rsx.Argon2PDefault}, "librsx"
	}
	return rsx.KDFParams{T: 2, M: 64 * 1024, P: 1}, "interactive"
}

func secretsAAD(db, path string) []byte {
	return []byte("redx-secrets/v1\n" + db + "\n" + path)
}

func checkSecretsPassword(pw string) error {
	if utf8.RuneCountInString(pw) < 8 {
		return se(400, "use a Red-SecretsXAI password of at least 8 characters. This is not your Red-XAI Account password. Nothing was written.")
	}
	if len(pw) > 1024 {
		return se(400, "that password is longer than 1024 bytes. Nothing was written.")
	}
	return nil
}

func checkSecretsPath(path string) error {
	if path == "" {
		return nil
	}
	if err := ValidPath(path); err != nil {
		return se(400, "that record path is not valid. Nothing was written.")
	}
	return nil
}

func (h *Host) sealWithPassword(pw, aad, pt []byte) (string, string, rsx.KDFParams, error) {
	if len(pt) > maxSecretsPlain {
		return "", "", rsx.KDFParams{}, se(400, fmt.Sprintf("plaintext is larger than %d bytes. Nothing was written.", maxSecretsPlain))
	}
	kp, profile := h.secretsKDF()
	dir, err := os.MkdirTemp("", "redx-rsx-")
	if err != nil {
		return "", "", kp, se(500, "Red-SecretsXAI could not start a seal. Nothing was written.")
	}
	defer os.RemoveAll(dir)
	kxaiPath := filepath.Join(dir, "session.kxai")
	sess, _, err := rsx.OpenSession(pw, kxaiPath, &rsx.SessionOptions{KDF: &kp})
	if err != nil {
		return "", "", kp, secretsSealErr(err)
	}
	defer sess.Close()
	blob, err := sess.SealC(aad, pt, rsx.BandAuto)
	if err != nil {
		return "", "", kp, secretsSealErr(err)
	}
	kxai, err := os.ReadFile(kxaiPath)
	if err != nil || len(kxai) == 0 {
		return "", "", kp, se(500, "Red-SecretsXAI could not finish the seal. Nothing was written.")
	}
	return envelopeBox(kxai, blob, kp, profile), profile, kp, nil
}

func secretsSealErr(err error) error {
	if errors.Is(err, rsx.ErrRange) {
		return se(503, "this host does not have enough free memory for the configured Argon2id profile. Nothing was written, and no stored data was changed. Use secrets_kdf = \"interactive\" or free memory and try again.")
	}
	return se(400, "Red-SecretsXAI rejected this seal. Nothing was written.")
}

func (h *Host) openWithPassword(pw, aad []byte, boxText string) ([]byte, error) {
	kxai, blob, err := parseEnvelope(boxText)
	if err != nil {
		return nil, err
	}
	dir, err := os.MkdirTemp("", "redx-rsx-")
	if err != nil {
		return nil, se(500, "Red-SecretsXAI could not start an open. Nothing was written.")
	}
	defer os.RemoveAll(dir)
	kxaiPath := filepath.Join(dir, "session.kxai")
	if err := os.WriteFile(kxaiPath, kxai, 0o600); err != nil {
		return nil, se(500, "Red-SecretsXAI could not start an open. Nothing was written.")
	}
	sess, _, err := rsx.OpenSession(pw, kxaiPath, &rsx.SessionOptions{ReadOnly: true})
	if err != nil {
		if errors.Is(err, rsx.ErrAuth) {
			return nil, se(422, "wrong Red-SecretsXAI password. Nothing was written.")
		}
		if errors.Is(err, rsx.ErrRange) {
			return nil, se(503, "this host does not have enough free memory to run Argon2id for this envelope. Nothing was written, and the envelope was not changed.")
		}
		return nil, se(422, "Red-SecretsXAI could not open this envelope. Nothing was written.")
	}
	defer sess.Close()
	pt, _, err := sess.OpenC(aad, blob, 0)
	if err != nil {
		return nil, se(422, "the password unlocked the envelope, but the sealed bytes do not match this record, or they were altered. Nothing was written.")
	}
	if !utf8.Valid(pt) {
		rsx.Wipe(pt)
		return nil, se(422, "the opened value is not text. Nothing was written.")
	}
	return pt, nil
}

func parseEnvelope(text string) (kxai, blob []byte, err error) {
	v, perr := box.ParseValue(strings.TrimSpace(text))
	if perr != nil || v.Kind != box.KindBox || v.Box == nil {
		return nil, nil, se(400, "this is not a Red-SecretsXAI envelope. AES pack ciphertext is not opened here, and nothing was rewritten.")
	}
	format, ok := entryString(v.Box, "Format")
	if !ok || format != secretsFormat {
		return nil, nil, se(400, "this is not a red-xai-encrypt/rsxc1 envelope. Existing pack encryption and other sealed formats were left unchanged.")
	}
	k, ok1 := entryString(v.Box, "KXAI")
	b, ok2 := entryString(v.Box, "Blob")
	if !ok1 || !ok2 {
		return nil, nil, se(400, "the envelope is missing Red-SecretsXAI fields. Nothing was written.")
	}
	kxai, err1 := base64.StdEncoding.DecodeString(strings.TrimSpace(k))
	blob, err2 := base64.StdEncoding.DecodeString(strings.TrimSpace(b))
	if err1 != nil || err2 != nil || len(kxai) == 0 || len(blob) == 0 {
		return nil, nil, se(400, "the envelope is not valid base64. Nothing was written.")
	}
	return kxai, blob, nil
}

func entryString(b *box.Box, key string) (string, bool) {
	e := b.Get(key, 0, false)
	if e == nil || e.Value.Kind != box.KindString {
		return "", false
	}
	return e.Value.Str, true
}

func envelopeBox(kxai, blob []byte, kp rsx.KDFParams, profile string) string {
	b := box.NewBox()
	str := func(k, v string) { b.Put(box.NewEntry(k, nil, box.String(v))) }
	num := func(k string, n int64) { b.Put(box.NewEntry(k, nil, box.Int(n))) }
	str("Format", secretsFormat)
	str("Engine", secretsEngine)
	str("Binding", "pure-go")
	str("Profile", profile)
	str("KDF", "argon2id")
	num("T", int64(kp.T))
	num("MKiB", int64(kp.M))
	num("P", int64(kp.P))
	str("Note", "Password seal of this value only. The password is not stored. Creating this envelope does not modify pack AES or any other sealed data.")
	str("KXAI", base64.StdEncoding.EncodeToString(kxai))
	str("Blob", base64.StdEncoding.EncodeToString(blob))
	return b.String()
}
