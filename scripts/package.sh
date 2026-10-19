#!/usr/bin/env bash
# Build installers into dist/.   usage: scripts/package.sh deb|windows|macos VERSION
#   deb      (Linux)  : redx_<ver>_{amd64,arm64,armhf}.deb          needs dpkg-deb
#   windows  (any OS) : redx-<ver>-windows-{amd64,arm64}-setup.exe  needs makensis (NSIS); UNSIGNED
#   macos    (macOS)  : redx-<ver>-macos-{arm64,amd64,universal}.{dmg,pkg}   needs hdiutil, pkgbuild, lipo; UNSIGNED
# `deb` and `windows` expect scripts/build.sh to have produced dist/redx-<ver>-<os>-<arch>/ first,
# and build the launcher themselves.
set -euo pipefail
cd "$(dirname "$0")/.."
KIND="$1"; VERSION="$2"; mkdir -p dist
LD="-s -w -X redx/host.Version=${VERSION}"
launcher() { # os arch goarm outfile [ldflags]: reuse the one scripts/build.sh already put in the archive folder (same bytes everywhere)
  [ -f "$4" ] && return 0
  GOOS=$1 GOARCH=$2 GOARM=${3:-} CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION} ${5:-}" -o "$4" ./cmd/redx-launcher
}
case "$KIND" in
  deb)
    for t in amd64 arm64 armv7; do
      d="dist/redx-${VERSION}-linux-$t"; [ -d "$d" ] || { echo "missing $d (run scripts/build.sh first)" >&2; exit 1; }
      ga=$t; goarm=""; [ "$t" = armv7 ] && { ga=arm; goarm=7; }
      launcher linux "$ga" "$goarm" "$d/redx-launcher"
      deploy/linux/build-deb.sh "$VERSION" "$t" "$d" dist
    done ;;
  windows)
    command -v makensis >/dev/null || { echo "makensis not found (apt install nsis)" >&2; exit 1; }
    # numeric X.Y.Z for the Windows version resource: "0.4.4-rc" -> 0.4.4, "1.2" -> 1.2.0
    NUMVERSION="$(printf '%s' "$VERSION" | sed -E 's/^v//; s/[^0-9.].*$//')"
    case "$NUMVERSION" in *.*.*) ;; *.*) NUMVERSION="$NUMVERSION.0" ;; "") NUMVERSION="0.0.0" ;; *) NUMVERSION="$NUMVERSION.0.0" ;; esac
    for t in amd64 arm64; do
      d="dist/redx-${VERSION}-windows-$t"; [ -d "$d" ] || { echo "missing $d (run scripts/build.sh first)" >&2; exit 1; }
      launcher windows "$t" "" "$d/redx-launcher.exe" "-H=windowsgui"
      # NSIS wants a plain 4-part product version
      makensis -V2 -DVERSION="${VERSION}" -DNUMVERSION="${NUMVERSION}" -DARCH="$t" -DSRC="$PWD/$d" -DICON="$PWD/assets/icons/redx.ico" \
        -DOUT="$PWD/dist/redx-${VERSION}-windows-$t-setup.exe" deploy/windows/redx.nsi
    done ;;
  macos)
    [ "$(uname -s)" = Darwin ] || { echo "macOS packaging runs on macOS only" >&2; exit 1; }
    deploy/macos/build-macos.sh "$VERSION" dist arm64 amd64 universal ;;
  *) echo "usage: $0 deb|windows|macos VERSION" >&2; exit 2 ;;
esac
