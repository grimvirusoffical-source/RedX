package host_test

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"redx/host"
	"redx/host/internal/stubstore"
)

// hosted_apps_aes.json was written by the pre-migration RedX (d1f2122): one app
// secret sealed with AES-256-GCM. Startup must refuse it clearly (naming the
// entry), never decrypt it, and leave the file alone.
func TestLegacyAESAppSecretsRefusedAtStartup(t *testing.T) {
	b, err := os.ReadFile("testdata/legacy/hosted_apps_aes.json")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	p := filepath.Join(dir, "hosted", "apps.json")
	_ = os.MkdirAll(filepath.Dir(p), 0o700)
	if err := os.WriteFile(p, b, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err = host.New(baseCfg(dir), func(d string, follower bool) (host.Backend, error) {
		return stubstore.Open(d, follower)
	}, t.Logf)
	if !errors.Is(err, host.ErrLegacyAppSecrets) || !strings.Contains(err.Error(), "app1/API_TOKEN") || !strings.Contains(err.Error(), "set the secrets again") {
		t.Fatalf("startup with AES app secrets: %v", err)
	}
	after, _ := os.ReadFile(p)
	if string(after) != string(b) {
		t.Fatal("refused apps.json was modified")
	}
}
