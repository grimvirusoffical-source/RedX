package main

import (
	"os"
	"testing"
)

// The scythe icon and version info are linked into the Windows executables through these committed resource files
// (regenerate with scripts/winres.sh). Without them the .exe silently has the generic Go icon.
func TestWindowsResourcesPresent(t *testing.T) {
	for _, arch := range []string{"amd64", "arm64"} {
		fi, err := os.Stat("rsrc_windows_" + arch + ".syso")
		if err != nil || fi.Size() < 20000 {
			t.Errorf("rsrc_windows_%s.syso missing or too small (run scripts/winres.sh): %v", arch, err)
		}
	}
}
