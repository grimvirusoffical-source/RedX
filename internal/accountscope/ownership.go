// Package accountscope defines integration-layer ownership, not database data.
package accountscope

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"strings"
	"unicode"
	"unicode/utf8"
)

const LegacyIssuer = "urn:redxai:legacy-site"
const FreshIssuer = "urn:redxai:fresh-normal-prototype:v1"
const Prefix = " rxf1:"

func ValidLegacySubject(s string) bool {
	return s != "" && len(s) <= 256 && utf8.ValidString(s) && strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) < 0
}
func ValidFreshSubject(s string) bool { return len(s) <= 200 && ValidLegacySubject(s) }
func PublicID(subject string) string {
	sum := sha256.Sum256([]byte(FreshIssuer + "\x00" + subject))
	return "rxf1_" + hex.EncodeToString(sum[:])
}

// Key is injective and reversible; its leading space is outside the accepted
// legacy-subject domain. Public DTO hashes are never ownership keys.
func Key(issuer, subject string) (string, bool) {
	if issuer != FreshIssuer || !ValidFreshSubject(subject) {
		return "", false
	}
	return Prefix + base64.RawURLEncoding.EncodeToString([]byte(issuer)) + "." + base64.RawURLEncoding.EncodeToString([]byte(subject)), true
}
func Decode(key string) (issuer, subject string, ok bool) {
	if !strings.HasPrefix(key, Prefix) {
		return "", "", false
	}
	parts := strings.Split(strings.TrimPrefix(key, Prefix), ".")
	if len(parts) != 2 {
		return "", "", false
	}
	i, e := base64.RawURLEncoding.DecodeString(parts[0])
	if e != nil {
		return "", "", false
	}
	s, e := base64.RawURLEncoding.DecodeString(parts[1])
	if e != nil {
		return "", "", false
	}
	want, valid := Key(string(i), string(s))
	return string(i), string(s), valid && want == key
}

// MetadataMatches treats omitted metadata as legacy only. No unlabelled
// space-prefixed record can ever be adopted as a fresh record.
func MetadataMatches(key, issuer, subject string) bool {
	if issuer == "" && subject == "" {
		return key == "" || ValidLegacySubject(key)
	}
	if issuer == LegacyIssuer {
		return ValidLegacySubject(key) && subject == key
	}
	want, ok := Key(issuer, subject)
	return ok && want == key
}
