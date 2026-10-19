#!/usr/bin/env bash
# Build RedX.app + .dmg + .pkg. Run on macOS (needs lipo, hdiutil, pkgbuild, plutil; all ship with macOS / Xcode CLT).
# usage: build-macos.sh VERSION OUTDIR ARCH  [ARCH ...]       ARCH = arm64 | amd64 | universal
#   binaries are built here with Go (cross-compiled; CGO off) from the repo root.
# UNSIGNED: Gatekeeper will say the app is from an unidentified developer (right-click -> Open).
set -euo pipefail
VERSION="$1"; OUT="$2"; shift 2
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
ICNS="${ICNS:-$ROOT/assets/icons/redx.icns}"
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
LD="-s -w -X redx/host.Version=${VERSION}"

build_bin() { # arch(go) outdir
  mkdir -p "$2"
  for c in redxd redx; do
    (cd "$ROOT" && GOOS=darwin GOARCH="$1" CGO_ENABLED=0 go build -trimpath -ldflags "$LD" -o "$2/$c" "./cmd/$c")
  done
  (cd "$ROOT" && GOOS=darwin GOARCH="$1" CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o "$2/redx-launcher" ./cmd/redx-launcher)
}

for ARCH in "$@"; do
  W="$(mktemp -d)"
  case "$ARCH" in
    arm64|amd64) build_bin "$ARCH" "$W/bin" ;;
    universal)
      build_bin arm64 "$W/a"; build_bin amd64 "$W/b"; mkdir -p "$W/bin"
      for c in redxd redx redx-launcher; do lipo -create -output "$W/bin/$c" "$W/a/$c" "$W/b/$c"; done ;;
    *) echo "bad arch $ARCH" >&2; exit 2 ;;
  esac
  NAME="redx-${VERSION}-macos-${ARCH}"
  APP="$W/RedX.app"
  mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources"
  cp "$W/bin/redx-launcher" "$APP/Contents/MacOS/RedX"
  cp "$W/bin/redxd" "$W/bin/redx" "$APP/Contents/MacOS/"
  # the launcher looks for redxd next to itself
  cp "$ICNS" "$APP/Contents/Resources/redx.icns"
  sed "s/@VERSION@/${VERSION}/g" "$ROOT/deploy/macos/Info.plist.in" > "$APP/Contents/Info.plist"
  plutil -lint "$APP/Contents/Info.plist"
  chmod 755 "$APP/Contents/MacOS/"*
  # ad-hoc signature only (free, no identity): makes the arm64 binaries launchable; still NOT notarized.
  codesign --force --deep --sign - "$APP" || echo "ad-hoc codesign failed (continuing)"

  # ---- .dmg (drag RedX to Applications) ----
  STAGE="$W/dmg"; mkdir -p "$STAGE"; cp -R "$APP" "$STAGE/"; ln -s /Applications "$STAGE/Applications"
  cp "$ROOT/deploy/macos/README-FIRST.txt" "$STAGE/READ ME FIRST.txt"
  hdiutil create -volname "RedX ${VERSION}" -srcfolder "$STAGE" -ov -format UDZO "$OUT/${NAME}.dmg"

  # ---- .pkg (installs RedX.app into /Applications, redx + redxd CLI into /usr/local/bin) ----
  PR="$W/pkgroot"; mkdir -p "$PR/Applications" "$PR/usr/local/bin"
  cp -R "$APP" "$PR/Applications/"
  cp "$W/bin/redx" "$W/bin/redxd" "$PR/usr/local/bin/"
  # not relocatable: otherwise Installer "updates" a RedX.app it finds elsewhere (e.g. ~/Applications) instead of /Applications
  CPL="$W/component.plist"
  pkgbuild --analyze --root "$PR" "$CPL"
  plutil -replace 0.BundleIsRelocatable -bool NO "$CPL"
  pkgbuild --root "$PR" --component-plist "$CPL" --identifier com.redx.pkg --version "${VERSION}" --install-location / "$OUT/${NAME}.pkg"
  rm -rf "$W"
  echo "built $OUT/${NAME}.dmg and .pkg"
done
