package main

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

// The icon and version info are linked into the Windows executables through rsrc_windows_*.syso files.
// They are build outputs: scripts/build.sh regenerates them for the version being built (0.4.4 shipped
// stale committed .syso files that said 0.4.3.0 and copyright "RedX").
func TestWindowsResourcesGeneratedForTheBuiltVersion(t *testing.T) {
	ws, err := os.ReadFile("../../scripts/winres.sh")
	if err != nil {
		t.Fatal(err)
	}
	w := string(ws)
	if !strings.Contains(w, `COPYRIGHT="Copyright (c) 2026 Red-XAI LLC"`) || !strings.Contains(w, `--copyright "$COPYRIGHT"`) {
		t.Error(`scripts/winres.sh must stamp LegalCopyright "Copyright (c) 2026 Red-XAI LLC"`)
	}
	if strings.Contains(w, `--copyright "RedX"`) {
		t.Error(`scripts/winres.sh still stamps the old copyright "RedX"`)
	}
	bs, err := os.ReadFile("../../scripts/build.sh")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(bs), `scripts/winres.sh "$VERSION"`) {
		t.Error("scripts/build.sh must regenerate the Windows resources for the version it builds")
	}
	if _, err := exec.LookPath("git"); err == nil {
		out, err := exec.Command("git", "ls-files", "--", "../../cmd/*/rsrc_windows_*.syso").Output()
		if err == nil && strings.TrimSpace(string(out)) != "" {
			t.Errorf("rsrc_windows_*.syso must not be committed (they go stale):\n%s", out)
		}
	}
}
