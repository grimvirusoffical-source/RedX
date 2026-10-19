package host

import (
	"os/exec"
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
	out, err := exec.Command(node, "--test", "uitest").CombinedOutput()
	if err != nil {
		t.Fatalf("console JS tests failed:\n%s", out)
	}
}
