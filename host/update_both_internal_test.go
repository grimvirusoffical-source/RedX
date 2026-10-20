package host

import (
	"encoding/json"
	"errors"
	"os"
	"testing"
)

func TestBothSourceMonotonicAndSignature(t *testing.T) {
	h := &Host{Cfg: Config{DataDir: t.TempDir(), HostedApps: []string{"widget"}}, NodeID: "n1"}
	u, err := openUpdater(h)
	if err != nil {
		t.Fatal(err)
	}
	if u.sourcePref(u.appLocked("widget")) != "both" {
		t.Fatal("hosted default source is both")
	}
	body, _, created, err := u.putManifest(testManifest("1.0.0", "host"))
	if err != nil || !created || manifestSeq(t, body) != 1 {
		t.Fatalf("host 1.0.0: created %v seq %d err %v", created, manifestSeq(t, body), err)
	}
	body, _, created, err = u.putManifest(testManifest("1.0.1", "github"))
	if err != nil || !created || manifestSeq(t, body) != 2 {
		t.Fatalf("github 1.0.1: created %v seq %d err %v", created, manifestSeq(t, body), err)
	}
	body, _, created, err = u.putManifest(testManifest("1.0.0", "github"))
	if err != nil || !created || manifestSeq(t, body) != 1 {
		t.Fatalf("same version shares sequence: created %v seq %d err %v", created, manifestSeq(t, body), err)
	}

	if err := u.setSource("widget", "host"); err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := u.putManifest(testManifest("1.1.0", "github")); !errors.Is(err, errNotHosted) {
		t.Fatalf("github ingest while source is host: %v", err)
	}
	if _, err := u.prepareApply(applyInput{App: "widget", Version: "1.0.1", Source: "github"}); !errors.Is(err, errNotHosted) {
		t.Fatalf("prepare github while source is host: %v", err)
	}

	u.mu.Lock()
	sm := u.st.Manifests[manifestKey("widget", "1.0.0", "host")]
	orig := append([]byte(nil), sm.Body...)
	sm.Body = append([]byte(nil), orig...)
	sm.Body[len(sm.Body)/2] ^= 0x1
	u.mu.Unlock()
	if _, _, _, err := u.loadManifest("widget", "1.0.0", "host"); !errors.Is(err, errBadSig) {
		t.Fatalf("tampered manifest: %v", err)
	}
	u.mu.Lock()
	sm.Body = orig
	u.mu.Unlock()

	if err := u.setSource("widget", "both"); err != nil {
		t.Fatal(err)
	}
	if _, err := u.prepareApply(applyInput{App: "widget", Version: "1.0.1", Source: "github"}); err != nil {
		t.Fatalf("both accepts github: %v", err)
	}
	got, err := u.chooseSource("widget", "1.0.1", "")
	if err != nil || got != "github" {
		t.Fatalf("both chooses github when that is the only source: %s %v", got, err)
	}
	if err := u.setSource("widget", "github"); err != nil {
		t.Fatal(err)
	}
	got, err = u.chooseSource("widget", "1.0.0", "")
	if err != nil || got != "github" {
		t.Fatalf("github pref does not fall back to host: %s %v", got, err)
	}
	if err := u.setSource("widget", "host"); err != nil {
		t.Fatal(err)
	}
	if _, err := u.chooseSource("widget", "1.0.1", ""); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("host pref ignores a github-only manifest: %v", err)
	}
}

func testManifest(version, kind string) *Manifest {
	m := &Manifest{
		App: "widget", Version: version, Channel: "stable",
		Source:   ManifestSource{Kind: kind},
		Outcome:  Outcome{Tags: []string{"+security"}},
		Requires: Requires{Restart: true},
	}
	if kind == "host" {
		m.Source.Host = &HostOrigin{BuildID: "b1", Commit: "abc"}
	} else {
		m.Source.GitHub = &GitHubOrigin{Repo: "red-xai/widget", Tag: "v" + version, Commit: "abc"}
	}
	return m
}

func manifestSeq(t *testing.T, body []byte) int64 {
	t.Helper()
	var m Manifest
	if err := json.Unmarshal(body, &m); err != nil {
		t.Fatal(err)
	}
	return m.Sequence
}
