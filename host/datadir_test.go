package host

import (
	"errors"
	"path/filepath"
	"testing"
)

func TestDefaultDataDirPerOS(t *testing.T) {
	env := func(m map[string]string) func(string) string { return func(k string) string { return m[k] } }
	home := func() (string, error) { return filepath.FromSlash("/home/ann"), nil }
	noHome := func() (string, error) { return "", errors.New("no home") }
	none := func(string) bool { return false }
	only := func(p string) func(string) bool { return func(x string) bool { return x == p } }
	J := filepath.Join
	cases := []struct {
		name, goos string
		env        map[string]string
		euid       int
		home       func() (string, error)
		exists     func(string) bool
		want       string
	}{
		{"windows per-user", "windows", map[string]string{"LOCALAPPDATA": `C:\U\ann\AppData\Local`, "ProgramData": `C:\ProgramData`}, 1000, home, none, J(`C:\U\ann\AppData\Local`, "RedX", "data")},
		{"windows keeps an old ProgramData install", "windows", map[string]string{"LOCALAPPDATA": `C:\L`, "ProgramData": `C:\ProgramData`}, 1000, home, only(J(`C:\ProgramData`, "RedX", "data")), J(`C:\ProgramData`, "RedX", "data")},
		{"windows without LOCALAPPDATA", "windows", map[string]string{"ProgramData": `C:\ProgramData`}, 1000, home, none, J(`C:\ProgramData`, "RedX", "data")},
		{"macOS normal user", "darwin", nil, 501, home, none, J("/home/ann", "Library", "Application Support", "RedX", "data")},
		{"macOS keeps the old system dir", "darwin", nil, 501, home, only("/usr/local/var/redx"), "/usr/local/var/redx"},
		{"macOS root", "darwin", nil, 0, home, none, "/usr/local/var/redx"},
		{"linux user", "linux", nil, 1000, home, none, J("/home/ann", ".redx", "data")},
		{"linux root", "linux", nil, 0, home, none, "/var/lib/redx"},
		{"no home at all", "linux", nil, 1000, noHome, none, "./redx-data"},
	}
	for _, c := range cases {
		if got := defaultDataDir(c.goos, env(c.env), c.euid, c.home, c.exists); got != c.want {
			t.Errorf("%s: got %q want %q", c.name, got, c.want)
		}
	}
}
