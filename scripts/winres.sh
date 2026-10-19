#!/usr/bin/env bash
# Generate the Windows resource files (icon + version info) that `go build` links into the .exe files.
# The .syso files are build outputs (git-ignored, never committed): scripts/build.sh runs this for every
# build with a Windows target, so the version resource always matches the version being built.
#   scripts/winres.sh 0.4.5          uses go-winres (installed, or `go run github.com/tc-hib/go-winres@v0.3.3`)
set -euo pipefail
cd "$(dirname "$0")/.."
VER="${1:?usage: scripts/winres.sh VERSION}"
VER="${VER#v}"
COPYRIGHT="Copyright (c) 2026 Red-XAI LLC"
if [ -n "${WINRES:-}" ]; then WR=("$WINRES")
elif command -v go-winres >/dev/null; then WR=(go-winres)
elif [ -x "$HOME/go/bin/go-winres" ]; then WR=("$HOME/go/bin/go-winres")
else WR=(go run github.com/tc-hib/go-winres@v0.3.3); fi
# numeric X.Y.Z.0 for the fixed file version: "0.4.5" -> 0.4.5.0, "0.4.5-rc1" -> 0.4.5.0; a non-numeric
# development version ("4eb0875", "v0.4.4-3-gabc") falls back to its numeric prefix or 0.0.0.0
NUM="$(printf '%s' "$VER" | sed -E 's/[^0-9.].*$//; s/\.$//')"
case "$NUM" in *.*.*.*) NUM="$(cut -d. -f1-3 <<<"$NUM")" ;; esac
case "$NUM" in *.*.*) ;; *.*) NUM="$NUM.0" ;; "") NUM="0.0.0" ;; *) NUM="$NUM.0.0" ;; esac
FV="$NUM.0"
ICO="$(pwd)/assets/icons/redx.ico"
gen() { # dir exe description manifest
  ( cd "cmd/$1" && rm -f rsrc_windows_*.syso && "${WR[@]}" simply --icon "$ICO" --manifest "$4" \
      --product-name "RedX" --file-description "$3" --original-filename "$2" \
      --file-version "$FV" --product-version "$VER" --copyright "$COPYRIGHT" \
      --arch amd64,arm64 --out rsrc )
}
gen redxd redxd.exe "RedX database host" cli
gen redx redx.exe "RedX command-line tool" cli
gen redx-launcher redx-launcher.exe "RedX launcher" gui
ls -la cmd/*/rsrc_windows_*.syso
