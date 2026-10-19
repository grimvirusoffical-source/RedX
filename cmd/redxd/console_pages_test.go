package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
)

// drive the real console in headless Chrome, every page in both themes, and fail on console errors, uncaught
// exceptions, in-page error boxes or external requests (scripts/ui-pages-test.js). Skipped when Node, playwright-core or
// Chrome are not installed (set PLAYWRIGHT_CORE and CHROME); CI's Linux job installs them and runs it.
func TestConsolePagesHeadlessChrome(t *testing.T) {
	if testing.Short() {
		t.Skip("short mode")
	}
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed")
	}
	dir := t.TempDir()
	ext := ""
	if runtime.GOOS == "windows" {
		ext = ".exe"
	}
	for _, c := range []string{"redxd", "redx"} {
		out, err := exec.Command("go", "build", "-o", filepath.Join(dir, c+ext), "redx/cmd/"+c).CombinedOutput()
		if err != nil {
			t.Fatalf("build %s: %v\n%s", c, err, out)
		}
	}
	script, _ := filepath.Abs(filepath.Join("..", "..", "scripts", "ui-pages-test.js"))
	cmd := exec.Command(node, script, filepath.Join(dir, "redxd"+ext), filepath.Join(dir, "redx"+ext))
	cmd.Env = os.Environ()
	out, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok && ee.ExitCode() == 77 {
		t.Skip(string(out))
	}
	if err != nil {
		t.Fatalf("console page test failed:\n%s", out)
	}
	t.Log(string(out))
}
