#!/usr/bin/env bash
# Regenerate the Windows resource files (icon + version info) that `go build` links into the .exe files.
# The .syso files are committed, so a normal `go build` embeds the icon; run this only when the icon or the version changes.
#   scripts/winres.sh 0.4.1          needs: go install github.com/tc-hib/go-winres@v0.3.3
set -euo pipefail
cd "$(dirname "$0")/.."
VER="${1:?usage: scripts/winres.sh X.Y.Z}"
WINRES="${WINRES:-$(command -v go-winres || echo "$HOME/go/bin/go-winres")}"
[ -x "$WINRES" ] || { echo "go-winres not found: go install github.com/tc-hib/go-winres@v0.3.3" >&2; exit 1; }
FV="${VER%%-*}.0"; [ "$(awk -F. '{print NF}' <<<"${VER%%-*}")" = 3 ] || { echo "version must be X.Y.Z" >&2; exit 1; }
ICO="$(pwd)/assets/icons/redx.ico"
gen() { # dir exe description manifest
  ( cd "cmd/$1" && rm -f rsrc_windows_*.syso && "$WINRES" simply --icon "$ICO" --manifest "$4" \
      --product-name "RedX" --file-description "$3" --original-filename "$2" \
      --file-version "$FV" --product-version "$VER" --copyright "RedX" \
      --arch amd64,arm64 --out rsrc )
}
gen redxd redxd.exe "RedX database host" cli
gen redx redx.exe "RedX command-line tool" cli
gen redx-launcher redx-launcher.exe "RedX launcher" gui
ls -la cmd/*/rsrc_windows_*.syso
