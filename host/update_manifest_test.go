package host

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestManifestSignVerifyTamperAndWrongKey(t *testing.T) {
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pub := priv.Public().(ed25519.PublicKey)
	m := &Manifest{
		Schema: updateManifestSchema, App: "redx", Version: "0.4.5", Channel: "stable", Sequence: 3,
		PublishedAt: time.Date(2026, 10, 19, 0, 0, 0, 0, time.UTC).Format(time.RFC3339),
		Source:      ManifestSource{Kind: "host", Host: &HostOrigin{BuildID: "hb_test", Commit: zeroCommit}},
		Outcome:     outcomeFromNotes([]string{"+security", "+stability"}, "Fixes a crash"),
		Requires:    Requires{Restart: true, Migrations: []string{}},
		Artifacts:   []Artifact{},
	}
	body, err := marshalManifest(m)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `"certificate":null`) || !strings.Contains(string(body), `"live_patch":[]`) {
		t.Fatalf("phase-1 AI fields: %s", body)
	}
	sig := signManifestBytes(priv, body)
	if !strings.HasPrefix(sig, "ed25519:") {
		t.Fatalf("sig %s", sig)
	}
	if err := verifyManifestBytes(pub, body, sig); err != nil {
		t.Fatal(err)
	}
	flipped := append([]byte(nil), body...)
	flipped[len(flipped)-2] ^= 0x01
	if err := verifyManifestBytes(pub, flipped, sig); err == nil {
		t.Fatal("tampered body verified")
	}
	_, other, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyManifestBytes(other.Public().(ed25519.PublicKey), body, sig); err == nil {
		t.Fatal("wrong key verified")
	}
	if err := verifyManifestBytes(pub, body, "ed25519:"+base64.StdEncoding.EncodeToString(make([]byte, ed25519.SignatureSize))); err == nil {
		t.Fatal("zero signature verified")
	}
}

func TestSemverPrecedence(t *testing.T) {
	order := []string{
		"1.0.0-alpha",
		"1.0.0-alpha.1",
		"1.0.0-alpha.beta",
		"1.0.0-beta",
		"1.0.0-beta.2",
		"1.0.0-beta.9",
		"1.0.0-beta.10",
		"1.0.0-beta.11",
		"1.0.0-rc.1",
		"1.0.0",
	}
	for i := range order {
		for j := range order {
			cmp, ok := semverCmp(order[i], order[j])
			if !ok {
				t.Fatalf("not semver: %s %s", order[i], order[j])
			}
			if cmp != cmpInt(i, j) {
				t.Fatalf("%s vs %s = %d, want %d", order[i], order[j], cmp, cmpInt(i, j))
			}
		}
	}
	if cmp, ok := semverCmp("3.0.0-beta.10", "3.0.0-beta.9"); !ok || cmp <= 0 {
		t.Fatalf("beta.10 vs beta.9 = %d ok=%v", cmp, ok)
	}
	if cmp, ok := semverCmp("v3.0.0-beta.10", "3.0.0-beta.9"); !ok || cmp <= 0 {
		t.Fatalf("v-prefix beta.10 = %d ok=%v", cmp, ok)
	}
	if cmp, ok := semverCmp("1.0.0+aaa", "1.0.0+zzz"); !ok || cmp != 0 {
		t.Fatalf("build metadata = %d ok=%v", cmp, ok)
	}
	if cmp, ok := semverCmp("1.0.0-alpha.1", "1.0.0"); !ok || cmp >= 0 {
		t.Fatalf("prerelease vs release = %d", cmp)
	}
}

func TestCheckSequence(t *testing.T) {
	if err := checkSequence(0, 1); err != nil {
		t.Fatal(err)
	}
	if err := checkSequence(4, 5); err != nil {
		t.Fatal(err)
	}
	if err := checkSequence(4, 4); err == nil {
		t.Fatal("equal sequence accepted")
	}
	if err := checkSequence(4, 3); err == nil {
		t.Fatal("regression accepted")
	}
	if err := checkSequence(0, 0); err == nil {
		t.Fatal("zero sequence accepted")
	}
}

func TestAssetLabelsAndGuessTags(t *testing.T) {
	cases := []struct {
		os, arch, kind string
		distinct       bool
		want           string
	}{
		{"macos", "arm64", "dmg", false, "RedX 0.4.5 (Mac, M1 chip)"},
		{"macos", "amd64", "pkg", false, "RedX 0.4.5 (Mac, Intel chip)"},
		{"macos", "universal", "dmg", false, "RedX 0.4.5 (Mac, Universal)"},
		{"windows", "amd64", "exe", false, "RedX 0.4.5 (Windows)"},
		{"windows", "arm64", "exe", false, "RedX 0.4.5 (Windows, ARM)"},
		{"linux", "amd64", "deb", false, "RedX 0.4.5 (Linux)"},
		{"linux", "arm64", "tar.gz", false, "RedX 0.4.5 (Linux, ARM64)"},
		{"linux", "armv7", "tar.gz", false, "RedX 0.4.5 (Linux, Raspberry Pi)"},
		{"macos", "arm64", "pkg", true, "RedX 0.4.5 (Mac, M1 chip) — Installer (.pkg)"},
		{"macos", "arm64", "dmg", true, "RedX 0.4.5 (Mac, M1 chip) — Disk image (.dmg)"},
		{"windows", "amd64", "exe", true, "RedX 0.4.5 (Windows) — Installer (.exe)"},
		{"windows", "amd64", "zip", true, "RedX 0.4.5 (Windows) — Portable (.zip)"},
		{"linux", "amd64", "deb", true, "RedX 0.4.5 (Linux) — Debian package (.deb)"},
		{"linux", "amd64", "tar.gz", true, "RedX 0.4.5 (Linux) — Archive (.tar.gz)"},
	}
	for _, c := range cases {
		got := assetLabel("redx", "0.4.5", c.os, c.arch, c.kind, c.distinct)
		if got != c.want {
			t.Errorf("label %s/%s/%s distinct=%v\n got %q\nwant %q", c.os, c.arch, c.kind, c.distinct, got, c.want)
		}
	}
	osName, arch, kind := classifyFilename("redx-0.4.5-macos-arm64.dmg")
	if osName != "macos" || arch != "arm64" || kind != "dmg" {
		t.Fatalf("classify %s %s %s", osName, arch, kind)
	}
	tags := guessTags("Security fix. Breaking change for the old flag.")
	joined := strings.Join(tags, " ")
	if !strings.Contains(joined, "+security") || !strings.Contains(joined, "-breaking") {
		t.Fatalf("guessTags %v", tags)
	}
	if err := validateOutcomeTags([]string{"+perf", "-compat"}); err != nil {
		t.Fatal(err)
	}
	if err := validateOutcomeTags([]string{"security"}); err == nil {
		t.Fatal("bare tag accepted")
	}
	if !cronMatches("* * * * *", time.Now().UTC()) {
		t.Fatal("star cron")
	}
	if !cronShape("0 0 1 1 0") {
		t.Fatal("cron shape")
	}
}

func TestSigningKeyFileModeRefused(t *testing.T) {
	if os.PathSeparator != '/' {
		t.Skip("mode bits")
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "signing.key")
	seed := make([]byte, ed25519.SeedSize)
	if _, err := rand.Read(seed); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(base64.StdEncoding.EncodeToString(seed)+"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := readSigningKeyFile(path, true); err == nil || !strings.Contains(err.Error(), "0600") && !strings.Contains(err.Error(), "600") {
		t.Fatalf("mode 0644 accepted: %v", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	k, _, err := readSigningKeyFile(path, true)
	if err != nil {
		t.Fatal(err)
	}
	if !k.Equal(ed25519.NewKeyFromSeed(seed)) {
		t.Fatal("seed mismatch")
	}
}
