#!/usr/bin/env bash
# Build RedX.app + .dmg + .pkg. Run on macOS (needs lipo, hdiutil, pkgbuild, plutil; all ship with macOS / Xcode CLT).
# usage: build-macos.sh VERSION OUTDIR ARCH  [ARCH ...]       ARCH = arm64 | amd64 | universal
#   binaries are built here with Go (cross-compiled; CGO off) from the repo root.
# UNSIGNED by default (ad-hoc signature only): Gatekeeper will say the app is from an unidentified developer
# (right-click -> Open). Signing with a Developer ID is opt-in and nothing here notarizes:
#   MACOS_SIGN_IDENTITY="Developer ID Application: ..."   signs every Mach-O (hardened runtime, timestamp)
#   MACOS_INSTALLER_IDENTITY="Developer ID Installer: ..."  signs the .pkg
set -euo pipefail
VERSION="$1"; OUT="$2"; shift 2
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
. "$ROOT/scripts/clean-tree.sh"
(cd "$ROOT" && require_clean_tree 1)  # installers are release builds: refuse a dirty tree (REDX_ALLOW_DIRTY=1 overrides)
case "$(cd "$ROOT" && git status --porcelain 2>/dev/null)" in "") ;; *) case "$VERSION" in *-dirty) ;; *) VERSION="${VERSION}-dirty";; esac;; esac
ICNS="${ICNS:-$ROOT/assets/icons/redx.icns}"
mkdir -p "$OUT"; OUT="$(cd "$OUT" && pwd)"
LD="-s -w -X redx/host.Version=${VERSION}"
IDENT="${MACOS_SIGN_IDENTITY:--}"

# sign_macho FILE: one Mach-O, explicitly (codesign --deep does not reach Contents/Resources, and a bare binary in
# /usr/local/bin is not part of any bundle). With a real identity a failure stops the build.
sign_macho() {
  if [ "$IDENT" = "-" ]; then
    codesign --force --sign - "$1" || { echo "ad-hoc codesign failed for $1" >&2; return 1; }
  else
    codesign --force --sign "$IDENT" --options runtime --timestamp "$1"
  fi
  codesign --verify --strict "$1"
}

# sign_app APP: inside-out, every nested Mach-O first, then the bundle itself (no --deep).
sign_app() {
  sign_macho "$1/Contents/Resources/bin/redx"
  sign_macho "$1/Contents/MacOS/redxd"
  if [ "$IDENT" = "-" ]; then
    codesign --force --sign - "$1/Contents/MacOS/RedX" && codesign --force --sign - "$1"
  else
    codesign --force --sign "$IDENT" --options runtime --timestamp "$1"
  fi
  codesign --verify --strict --deep "$1"
}

build_bin() { # arch(go) outdir
  mkdir -p "$2"
  for c in redxd redx; do
    (cd "$ROOT" && GOOS=darwin GOARCH="$1" CGO_ENABLED=0 go build -trimpath -ldflags "$LD" -o "$2/$c" "./cmd/$c")
  done
  (cd "$ROOT" && GOOS=darwin GOARCH="$1" CGO_ENABLED=0 go build -trimpath -ldflags "-s -w -X main.version=${VERSION}" -o "$2/redx-launcher" ./cmd/redx-launcher)
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
  mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources/bin"
  # the launcher looks for redxd next to itself. The redx CLI goes to Resources/bin: macOS file systems are
  # usually case-insensitive, so MacOS/redx would overwrite the launcher MacOS/RedX.
  cp "$W/bin/redx-launcher" "$APP/Contents/MacOS/RedX"
  cp "$W/bin/redxd" "$APP/Contents/MacOS/"
  cp "$W/bin/redx" "$APP/Contents/Resources/bin/redx"
  cp "$ICNS" "$APP/Contents/Resources/redx.icns"
  sed "s/@VERSION@/${VERSION}/g" "$ROOT/deploy/macos/Info.plist.in" > "$APP/Contents/Info.plist"
  plutil -lint "$APP/Contents/Info.plist"
  chmod 755 "$APP/Contents/MacOS/"* "$APP/Contents/Resources/bin/redx"
  # ad-hoc by default (free, no identity: makes the arm64 binaries launchable); still NOT notarized.
  sign_app "$APP"

  # ---- .dmg (drag RedX to Applications) ----
  STAGE="$W/dmg"; mkdir -p "$STAGE"; cp -R "$APP" "$STAGE/"; ln -s /Applications "$STAGE/Applications"
  cp "$ROOT/deploy/macos/README-FIRST.txt" "$STAGE/READ ME FIRST.txt"
  hdiutil create -volname "RedX ${VERSION}" -srcfolder "$STAGE" -ov -format UDZO "$OUT/${NAME}.dmg"

  # ---- .pkg (installs RedX.app into /Applications, redx + redxd CLI into /usr/local/bin) ----
  PR="$W/pkgroot"; mkdir -p "$PR/Applications" "$PR/usr/local/bin"
  cp -R "$APP" "$PR/Applications/"
  # the CLI copies are the app's already signed binaries (each signed on its own, before pkgbuild)
  cp "$APP/Contents/Resources/bin/redx" "$APP/Contents/MacOS/redxd" "$PR/usr/local/bin/"
  for b in "$PR/usr/local/bin/redx" "$PR/usr/local/bin/redxd"; do codesign --verify --strict "$b"; done
  # not relocatable: otherwise Installer "updates" a RedX.app it finds elsewhere (e.g. ~/Applications) instead of /Applications
  CPL="$W/component.plist"
  pkgbuild --analyze --root "$PR" "$CPL"
  plutil -replace 0.BundleIsRelocatable -bool NO "$CPL"
  PKGSIGN=()
  [ -n "${MACOS_INSTALLER_IDENTITY:-}" ] && PKGSIGN=(--sign "$MACOS_INSTALLER_IDENTITY" --timestamp)
  pkgbuild --root "$PR" --component-plist "$CPL" --identifier com.redx.pkg --version "${VERSION}" --install-location / ${PKGSIGN[@]+"${PKGSIGN[@]}"} "$OUT/${NAME}.pkg"
  rm -rf "$W"
  echo "built $OUT/${NAME}.dmg and .pkg"
done
