package host

import (
	"os/exec"
	"path/filepath"
	"testing"
)

// TestJSTokenizerSuite runs the console's pure-JS unit tests (tokenizers, QR, zip) with Node's
// built-in test runner. Node is a development-time tool only: the console itself needs no Node
// and no build step, so the test is skipped when node is missing.
func TestJSTokenizerSuite(t *testing.T) {
	node, err := exec.LookPath("node")
	if err != nil {
		t.Skip("node not installed; skipping console JS unit tests")
	}
	// name the files: newer Node versions treat a bare directory argument as a module to run
	files, _ := filepath.Glob(filepath.Join("uitest", "*.test.mjs"))
	if len(files) == 0 {
		t.Fatal("no console JS test files found in uitest/")
	}
	out, err := exec.Command(node, append([]string{"--test"}, files...)...).CombinedOutput()
	if err != nil {
		t.Fatalf("console JS tests failed:\n%s", out)
	}
}
