package host

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"time"
	"unicode"
)

// Manifest schema redx.update-manifest/v1. The signed bytes are the exact JSON
// object returned by GET .../manifests/{version}; clients verify that signature,
// then each artifact sha256, and refuse a sequence that is not strictly newer
// than the last one they accepted.
const updateManifestSchema = "redx.update-manifest/v1"

// Outcome tag vocabulary. A leading + adds or improves; a leading - removes or breaks.
var outcomeVocab = map[string]bool{
	"security": true, "perf": true, "stability": true,
	"capability": true, "breaking": true, "compat": true,
}

// Manifest is one release of one app.
type Manifest struct {
	Schema      string         `json:"schema"`
	App         string         `json:"app"`
	Version     string         `json:"version"`
	Channel     string         `json:"channel"`
	PublishedAt string         `json:"published_at"`
	Sequence    int64          `json:"sequence"`
	Source      ManifestSource `json:"source"`
	Outcome     Outcome        `json:"outcome"`
	Requires    Requires       `json:"requires"`
	Artifacts   []Artifact     `json:"artifacts"`
	LivePatch   []LivePatch    `json:"live_patch"`
	Certificate *Certificate   `json:"certificate"`
}

// ManifestSource names where the release came from. The inactive side is null.
type ManifestSource struct {
	Kind   string        `json:"kind"`
	GitHub *GitHubOrigin `json:"github"`
	Host   *HostOrigin   `json:"host"`
}

// GitHubOrigin is a GitHub release the host verified before signing.
type GitHubOrigin struct {
	Repo      string `json:"repo"`
	Tag       string `json:"tag"`
	Commit    string `json:"commit"`
	ReleaseID int64  `json:"release_id"`
}

// HostOrigin is a package built on this host.
type HostOrigin struct {
	BuildID string `json:"build_id"`
	Commit  string `json:"commit"`
}

// Outcome is the human-facing description of a release. Phase 1 fills summary
// and risk from release notes (or a small heuristic). Certificate stays null
// until phase 2.
type Outcome struct {
	Tags        []string `json:"tags"`
	Summary     string   `json:"summary"`
	Risk        *Risk    `json:"risk"`
	ChangelogMD string   `json:"changelog_md"`
}

// Risk is a 0..1 score. Level is low, medium, high or critical.
type Risk struct {
	Score   float64  `json:"score"`
	Level   string   `json:"level"`
	Reasons []string `json:"reasons"`
}

// Requires is what an install needs. Migrations may be empty.
type Requires struct {
	MinFrom    string   `json:"min_from"`
	Restart    bool     `json:"restart"`
	Migrations []string `json:"migrations"`
}

// Artifact is one downloadable file.
type Artifact struct {
	ID        string   `json:"id"`
	Label     string   `json:"label"`
	OS        string   `json:"os"`
	Arch      string   `json:"arch"`
	Kind      string   `json:"kind"`
	Filename  string   `json:"filename"`
	URL       string   `json:"url"`
	Mirrors   []string `json:"mirrors"`
	Size      int64    `json:"size"`
	SHA256    string   `json:"sha256"`
	DeltaFrom *string  `json:"delta_from"`
}

// LivePatch is a non-structural change applied without a restart (phase 2).
// The field is present from day one and is an empty array until then.
type LivePatch struct {
	Target string `json:"target"`
	Path   string `json:"path"`
	Op     string `json:"op"`
	SHA256 string `json:"sha256"`
	URL    string `json:"url"`
}

// Certificate is the phase-2 AI change certificate. It is null in phase 1.
type Certificate struct {
	Model          string        `json:"model"`
	AnalysedCommit string        `json:"analysed_commit"`
	Findings       []interface{} `json:"findings"`
}

// UpdateEvent is one message on GET /v1/updates/events.
// The same types may also arrive on the Accounts poll GET /v1/apps/events and are forwarded here.
type UpdateEvent struct {
	Type      string `json:"type"`
	App       string `json:"app"`
	Version   string `json:"version"`
	Source    string `json:"source"`
	RolloutID string `json:"rollout_id,omitempty"`
	State     string `json:"state,omitempty"`
}

func emptyStrings(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

// normalizeManifest fills slices so the signed JSON uses [] rather than null.
func normalizeManifest(m *Manifest) {
	if m.Outcome.Tags == nil {
		m.Outcome.Tags = []string{}
	}
	if m.Outcome.Risk != nil && m.Outcome.Risk.Reasons == nil {
		m.Outcome.Risk.Reasons = []string{}
	}
	if m.Requires.Migrations == nil {
		m.Requires.Migrations = []string{}
	}
	if m.Artifacts == nil {
		m.Artifacts = []Artifact{}
	}
	for i := range m.Artifacts {
		if m.Artifacts[i].Mirrors == nil {
			m.Artifacts[i].Mirrors = []string{}
		}
	}
	if m.LivePatch == nil {
		m.LivePatch = []LivePatch{}
	}
	if m.Source.Kind == "host" {
		m.Source.GitHub = nil
	}
	if m.Source.Kind == "github" {
		m.Source.Host = nil
	}
}

// marshalManifest returns the exact bytes that are signed and served.
func marshalManifest(m *Manifest) ([]byte, error) {
	normalizeManifest(m)
	return json.Marshal(m)
}

// signManifestBytes signs the exact body with Ed25519. The header value is
// "ed25519:" plus standard base64 of the 64-byte signature.
func signManifestBytes(priv ed25519.PrivateKey, body []byte) string {
	sig := ed25519.Sign(priv, body)
	return "ed25519:" + base64.StdEncoding.EncodeToString(sig)
}

// verifyManifestBytes checks an Ed25519 signature over the exact body.
// sigHeader is "ed25519:<base64>" or the raw base64.
func verifyManifestBytes(pub ed25519.PublicKey, body []byte, sigHeader string) error {
	raw, err := decodeSig(sigHeader)
	if err != nil {
		return err
	}
	if !ed25519.Verify(pub, body, raw) {
		return errors.New("bad signature")
	}
	return nil
}

func decodeSig(s string) ([]byte, error) {
	s = strings.TrimSpace(s)
	s = strings.TrimPrefix(s, "ed25519:")
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil || len(b) != ed25519.SignatureSize {
		return nil, errors.New("bad signature")
	}
	return b, nil
}

// checkSequence refuses next when it is not strictly newer than last.
// last == 0 means the app has never accepted a manifest.
func checkSequence(last, next int64) error {
	if next <= 0 {
		return fmt.Errorf("sequence %d is not positive", next)
	}
	if last > 0 && next <= last {
		return fmt.Errorf("sequence %d is not newer than %d", next, last)
	}
	return nil
}

// semver is major.minor.patch with an optional leading v and an optional pre-release.
// A release (no pre-release) is newer than the same numbers with a pre-release.
type semver struct {
	major, minor, patch int
	pre                 string
}

func parseSemver(s string) (semver, bool) {
	s = strings.TrimPrefix(strings.TrimPrefix(s, "v"), "V")
	pre := ""
	if i := strings.IndexAny(s, "-+"); i >= 0 {
		if s[i] == '-' {
			pre = s[i+1:]
			if j := strings.Index(pre, "+"); j >= 0 {
				pre = pre[:j]
			}
		}
		s = s[:i]
	}
	parts := strings.Split(s, ".")
	if len(parts) == 0 || len(parts) > 3 {
		return semver{}, false
	}
	nums := [3]int{}
	for i, p := range parts {
		if p == "" {
			return semver{}, false
		}
		n, err := strconv.Atoi(p)
		if err != nil || n < 0 {
			return semver{}, false
		}
		nums[i] = n
	}
	return semver{major: nums[0], minor: nums[1], patch: nums[2], pre: pre}, true
}

// semverCmp returns -1, 0, 1. A version that is not semver does not compare.
func semverCmp(a, b string) (int, bool) {
	av, aok := parseSemver(a)
	bv, bok := parseSemver(b)
	if !aok || !bok {
		return 0, false
	}
	if av.major != bv.major {
		return cmpInt(av.major, bv.major), true
	}
	if av.minor != bv.minor {
		return cmpInt(av.minor, bv.minor), true
	}
	if av.patch != bv.patch {
		return cmpInt(av.patch, bv.patch), true
	}
	switch {
	case av.pre == bv.pre:
		return 0, true
	case av.pre == "":
		return 1, true
	case bv.pre == "":
		return -1, true
	case av.pre < bv.pre:
		return -1, true
	default:
		return 1, true
	}
}

func cmpInt(a, b int) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// parseOutcomeTag accepts "+security" or "-breaking".
func parseOutcomeTag(s string) error {
	if len(s) < 2 || (s[0] != '+' && s[0] != '-') {
		return fmt.Errorf("outcome tag %q must start with + or -", s)
	}
	if !outcomeVocab[s[1:]] {
		return fmt.Errorf("outcome tag %q is not in the vocabulary", s)
	}
	return nil
}

func validateOutcomeTags(tags []string) error {
	for _, t := range tags {
		if err := parseOutcomeTag(t); err != nil {
			return err
		}
	}
	return nil
}

// outcomeFromNotes builds the phase-1 outcome. Summary is the first line of the
// release notes. Risk is a small heuristic over the tags (not a model).
func outcomeFromNotes(tags []string, notes string) Outcome {
	tags = emptyStrings(append([]string(nil), tags...))
	summary := ""
	for _, line := range strings.Split(notes, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			summary = line
			break
		}
	}
	if summary == "" && len(tags) > 0 {
		summary = strings.Join(tags, " ")
	}
	if len(summary) > 200 {
		summary = summary[:200]
	}
	return Outcome{Tags: tags, Summary: summary, Risk: heuristicRisk(tags), ChangelogMD: notes}
}

func heuristicRisk(tags []string) *Risk {
	score := 0.12
	reasons := []string{}
	for _, t := range tags {
		switch t {
		case "-breaking":
			score += 0.45
			reasons = append(reasons, "breaking change")
		case "-compat":
			score += 0.25
			reasons = append(reasons, "compatibility removal")
		case "-security":
			score += 0.40
			reasons = append(reasons, "security regression")
		case "+security":
			score += 0.05
			reasons = append(reasons, "security fix")
		case "-stability":
			score += 0.20
			reasons = append(reasons, "stability regression")
		case "+perf":
			reasons = append(reasons, "performance change")
		case "+capability":
			reasons = append(reasons, "new capability")
		case "+stability":
			reasons = append(reasons, "stability fix")
		case "+compat":
			reasons = append(reasons, "compatibility improvement")
		case "-capability":
			score += 0.15
			reasons = append(reasons, "capability removal")
		case "-perf":
			score += 0.10
			reasons = append(reasons, "performance regression")
		case "+breaking":
			score += 0.15
			reasons = append(reasons, "breaking tag")
		}
	}
	if len(reasons) == 0 {
		reasons = []string{"no outcome tags"}
	}
	if score > 1 {
		score = 1
	}
	score = math.Round(score*100) / 100
	level := "low"
	switch {
	case score >= 0.75:
		level = "critical"
	case score >= 0.50:
		level = "high"
	case score >= 0.30:
		level = "medium"
	}
	return &Risk{Score: score, Level: level, Reasons: reasons}
}

// guessTags reads a few words out of release notes when the publisher did not send tags.
func guessTags(notes string) []string {
	n := strings.ToLower(notes)
	var tags []string
	add := func(t string) {
		for _, e := range tags {
			if e == t {
				return
			}
		}
		tags = append(tags, t)
	}
	if strings.Contains(n, "cve") || strings.Contains(n, "security") {
		add("+security")
	}
	if strings.Contains(n, "performance") || strings.Contains(n, "faster") || strings.Contains(n, "latency") {
		add("+perf")
	}
	if strings.Contains(n, "break") || strings.Contains(n, "incompatible") {
		add("-breaking")
	}
	if strings.Contains(n, "crash") || strings.Contains(n, "stability") {
		add("+stability")
	}
	return tags
}

func productName(app string) string {
	if strings.EqualFold(app, "redx") {
		return "RedX"
	}
	if app == "" {
		return "App"
	}
	r := []rune(app)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

func platformPhrase(osName, arch string) (string, bool) {
	switch osName {
	case "macos":
		switch arch {
		case "arm64":
			return "Mac, M1 chip", true
		case "amd64":
			return "Mac, Intel chip", true
		case "universal":
			return "Mac, Universal", true
		}
	case "windows":
		switch arch {
		case "amd64":
			return "Windows", true
		case "arm64":
			return "Windows, ARM", true
		}
	case "linux":
		switch arch {
		case "amd64":
			return "Linux", true
		case "arm64":
			return "Linux, ARM64", true
		case "armv7":
			return "Linux, Raspberry Pi", true
		}
	}
	return "", false
}

func kindSuffix(kind string) string {
	switch kind {
	case "pkg":
		return " — Installer (.pkg)"
	case "dmg":
		return " — Disk image (.dmg)"
	case "exe":
		return " — Installer (.exe)"
	case "zip":
		return " — Portable (.zip)"
	case "deb":
		return " — Debian package (.deb)"
	case "tar.gz":
		return " — Archive (.tar.gz)"
	default:
		return ""
	}
}

// assetLabel builds Josh's release name. distinct is true when another artifact
// shares the same OS and CPU, so the installer kind is added.
func assetLabel(app, version, osName, arch, kind string, distinct bool) string {
	phrase, ok := platformPhrase(osName, arch)
	name := productName(app) + " " + version
	if !ok {
		if osName == "" && arch == "" {
			return name
		}
		return name + " (" + strings.TrimSpace(osName+" "+arch) + ")"
	}
	label := name + " (" + phrase + ")"
	if distinct {
		label += kindSuffix(kind)
	}
	return label
}

func applyDistinctLabels(app, version string, arts []Artifact) {
	type key struct{ os, arch string }
	n := map[key]int{}
	for _, a := range arts {
		n[key{a.OS, a.Arch}]++
	}
	for i := range arts {
		if strings.TrimSpace(arts[i].Label) != "" {
			continue
		}
		distinct := n[key{arts[i].OS, arts[i].Arch}] > 1
		arts[i].Label = assetLabel(app, version, arts[i].OS, arts[i].Arch, arts[i].Kind, distinct)
	}
}

func normOS(s string) string {
	switch strings.ToLower(s) {
	case "mac", "macos", "darwin", "osx":
		return "macos"
	case "win", "windows":
		return "windows"
	case "linux":
		return "linux"
	default:
		return strings.ToLower(s)
	}
}

func normArch(s string) string {
	switch strings.ToLower(s) {
	case "x64", "x86_64", "amd64":
		return "amd64"
	case "aarch64", "arm64":
		return "arm64"
	case "armv7", "armhf", "arm":
		return "armv7"
	case "universal":
		return "universal"
	default:
		return strings.ToLower(s)
	}
}

func kindFromFilename(name string) string {
	low := strings.ToLower(name)
	switch {
	case strings.HasSuffix(low, ".tar.gz"):
		return "tar.gz"
	case strings.HasSuffix(low, ".dmg"):
		return "dmg"
	case strings.HasSuffix(low, ".pkg"):
		return "pkg"
	case strings.HasSuffix(low, ".exe"):
		return "exe"
	case strings.HasSuffix(low, ".zip"):
		return "zip"
	case strings.HasSuffix(low, ".deb"):
		return "deb"
	default:
		return ""
	}
}

func classifyFilename(name string) (osName, arch, kind string) {
	kind = kindFromFilename(name)
	base := name
	for _, ext := range []string{".tar.gz", ".dmg", ".pkg", ".exe", ".zip", ".deb"} {
		if strings.HasSuffix(strings.ToLower(base), ext) {
			base = base[:len(base)-len(ext)]
			break
		}
	}
	for _, p := range strings.FieldsFunc(base, func(r rune) bool { return r == '-' || r == '_' || r == '.' }) {
		switch normOS(p) {
		case "macos", "windows", "linux":
			if osName == "" && (p == "macos" || p == "windows" || p == "linux" || strings.EqualFold(p, "darwin") || strings.EqualFold(p, "win") || strings.EqualFold(p, "mac")) {
				osName = normOS(p)
			}
		}
		switch strings.ToLower(p) {
		case "arm64", "aarch64", "amd64", "x64", "x86_64", "universal", "armv7", "armhf":
			arch = normArch(p)
		}
	}
	return osName, arch, kind
}

func validAppID(s string) bool {
	if len(s) < 1 || len(s) > 63 {
		return false
	}
	for i, r := range s {
		ok := (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '-' || r == '_'
		if i == 0 && (r < 'a' || r > 'z') && (r < '0' || r > '9') {
			return false
		}
		if !ok {
			return false
		}
	}
	return !strings.Contains(s, "..")
}

func validVersion(s string) bool {
	if len(s) < 1 || len(s) > 64 || strings.Contains(s, "..") || strings.ContainsAny(s, "/\\ ") {
		return false
	}
	for i, r := range s {
		ok := unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' || r == '+' || r == '-'
		if i == 0 && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
		if !ok {
			return false
		}
	}
	return true
}

func validArtifactID(s string) bool {
	if len(s) < 1 || len(s) > 80 || strings.Contains(s, "..") {
		return false
	}
	for i, r := range s {
		ok := unicode.IsLetter(r) || unicode.IsDigit(r) || r == '.' || r == '_' || r == '-'
		if i == 0 && !unicode.IsLetter(r) && !unicode.IsDigit(r) {
			return false
		}
		if !ok {
			return false
		}
	}
	return true
}

func validSHA256(s string) bool {
	if len(s) != 64 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func validCommit(s string) bool {
	if len(s) != 40 {
		return false
	}
	_, err := hex.DecodeString(s)
	return err == nil
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// cronMatches reports whether a 5-field UTC cron expression matches t.
// Empty matches always. Supported field forms: *, n, n-m, comma lists, */n.
func cronMatches(expr string, t time.Time) bool {
	expr = strings.TrimSpace(expr)
	if expr == "" || expr == "null" {
		return true
	}
	f := strings.Fields(expr)
	if len(f) != 5 {
		return false
	}
	t = t.UTC()
	vals := []int{t.Minute(), t.Hour(), t.Day(), int(t.Month()), int(t.Weekday())}
	for i := range f {
		if !cronField(f[i], vals[i]) {
			return false
		}
	}
	return true
}

func cronField(field string, v int) bool {
	for _, part := range strings.Split(field, ",") {
		part = strings.TrimSpace(part)
		if part == "*" {
			return true
		}
		if strings.HasPrefix(part, "*/") {
			n, err := strconv.Atoi(part[2:])
			if err != nil || n <= 0 {
				continue
			}
			if v%n == 0 {
				return true
			}
			continue
		}
		if a, b, ok := strings.Cut(part, "-"); ok {
			lo, e1 := strconv.Atoi(a)
			hi, e2 := strconv.Atoi(b)
			if e1 == nil && e2 == nil && v >= lo && v <= hi {
				return true
			}
			continue
		}
		n, err := strconv.Atoi(part)
		if err == nil && n == v {
			return true
		}
	}
	return false
}

// zeroCommit is used when a host-built package has no git commit to name.
// It is 40 hex zeroes, not a claim that the tree was committed.
const zeroCommit = "0000000000000000000000000000000000000000"
