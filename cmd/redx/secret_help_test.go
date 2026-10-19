package main

import (
	"strings"
	"testing"
)

// "-h" printed the full REDX_KEY as the flag default. No secret may ever appear in help output.
func TestHelpNeverShowsSecretsFromEnv(t *testing.T) {
	const dummy = "rx_" + "live_" + "DUMMYdummyDUMMYdummy0123456789abcdefgh" // split so secret scanners do not flag a test dummy
	t.Setenv("REDX_JOIN", "https://127.0.0.1:7777/#/join?c=RX-SECRT-CODEX&pin=00")
	t.Setenv("REDX_KEYSTORE_PASSPHRASE", "pass-DUMMY-phrase")
	cmds := [][]string{{"-h"}, {"help"}, {"key", "rotate", "-h"}, {"key", "create", "-h"}, {"key", "list", "-h"}, {"db", "list", "-h"},
		{"get", "-h"}, {"set", "-h"}, {"query", "-h"}, {"stats", "-h"}, {"subscribe", "-h"}, {"node", "status", "-h"}, {"node", "token", "-h"},
		{"node", "join", "-h"}, {"node", "repoint", "-h"}, {"node", "promote", "-h"}, {"doctor", "-h"}, {"backup", "-h"}, {"restore", "-h"},
		{"bx", "-h"}, {"pack", "list", "-h"}, {"media", "list", "-h"}, {"pulse", "list", "-h"}, {"idx", "list", "-h"}, {"sec", "show", "-h"}, {"preset", "-h"}}
	sawKeyFlag := false
	for _, c := range cmds {
		so, se, _ := runCLI(t, "http://127.0.0.1:1", dummy, c...)
		out := so + se
		for _, secret := range []string{dummy, "DUMMYdummy", "RX-SECRT-CODEX", "pass-DUMMY-phrase"} {
			if strings.Contains(out, secret) {
				t.Fatalf("redx %v leaks a secret in its help output", c) // never print the output itself: it holds the secret
			}
		}
		if strings.Contains(out, "-key") && strings.Contains(out, "$REDX_KEY") {
			sawKeyFlag = true
			if !strings.Contains(out, "currently set from $REDX_KEY") {
				t.Fatalf("redx %v: --key help should say the value comes from $REDX_KEY", c)
			}
		}
	}
	if !sawKeyFlag {
		t.Fatal("no help output mentioned --key and $REDX_KEY")
	}
}
