package accountscope

import (
	"strings"
	"testing"
)

func TestOwnershipKeysAreDisjointReversibleAndCanonical(t *testing.T) {
	for subject, want := range map[string]string{
		"same-subject": " rxf1:dXJuOnJlZHhhaTpmcmVzaC1ub3JtYWwtcHJvdG90eXBlOnYx.c2FtZS1zdWJqZWN0",
		"normal-ü-😀":   " rxf1:dXJuOnJlZHhhaTpmcmVzaC1ub3JtYWwtcHJvdG90eXBlOnYx.bm9ybWFsLcO8LfCfmIA",
	} {
		if got, ok := Key(FreshIssuer, subject); !ok || got != want {
			t.Fatal("independent Python/JS/Go private-key vector mismatch")
		}
	}
	seen := map[string]bool{}
	for _, subject := range []string{"same-subject", "normal-ü-😀", "rxf1_legacy", PublicID("same-subject"), strings.Repeat("x", 200)} {
		key, ok := Key(FreshIssuer, subject)
		if !ok || seen[key] || ValidLegacySubject(key) || key == PublicID(subject) {
			t.Fatal("non-disjoint ownership key")
		}
		seen[key] = true
		issuer, raw, ok := Decode(key)
		if !ok || issuer != FreshIssuer || raw != subject || !MetadataMatches(key, issuer, raw) {
			t.Fatal("tuple did not round trip")
		}
		if MetadataMatches(key, "", "") || MetadataMatches(key, LegacyIssuer, key) || MetadataMatches(PublicID(subject), issuer, raw) {
			t.Fatal("unlabelled/legacy/public DTO became fresh ownership")
		}
		if !MetadataMatches(PublicID(subject), "", "") {
			t.Fatal("valid legacy public-shaped ID changed")
		}
		for _, invalid := range []string{strings.TrimSpace(key), key + "=", key + ".", key + "\n"} {
			if _, _, ok := Decode(invalid); ok {
				t.Fatal("noncanonical key accepted")
			}
		}
	}
}

func TestOwnershipSubjectDomainAndUnknownIssuers(t *testing.T) {
	for _, subject := range []string{"", " a", "a ", "a\tb", "a\x00b", "a\u00a0b", "\xff", strings.Repeat("x", 201)} {
		if _, ok := Key(FreshIssuer, subject); ok {
			t.Fatal("invalid fresh subject accepted")
		}
	}
	if !ValidLegacySubject(strings.Repeat("x", 256)) || ValidLegacySubject(strings.Repeat("x", 257)) {
		t.Fatal("legacy length contract changed")
	}
	for _, issuer := range []string{"", LegacyIssuer, FreshIssuer + "/", "urn:attacker"} {
		if _, ok := Key(issuer, "normal"); ok {
			t.Fatal("unknown ownership issuer accepted")
		}
	}
}
