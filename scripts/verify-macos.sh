#!/usr/bin/env bash
# Verifies the unsigned macOS .dmg/.pkg on a real macOS machine/runner. usage: scripts/verify-macos.sh DISTDIR VERSION
set -uo pipefail
DIST="$(cd "$1" && pwd)"; V="$2"; fail=0
ok() { echo "PASS  $*"; }; bad() { echo "FAIL  $*"; fail=1; }
HOSTARCH=$(uname -m); echo "host arch: $HOSTARCH  macOS $(sw_vers -productVersion)"
DMG="$DIST/redx-$V-macos-universal.dmg"; PKG="$DIST/redx-$V-macos-universal.pkg"
[ -f "$DMG" ] && ok "universal dmg exists" || { bad "no dmg"; exit 1; }
MNT=$(mktemp -d)
hdiutil attach -nobrowse -readonly -mountpoint "$MNT" "$DMG" >/dev/null && ok "dmg mounts" || { bad "dmg mount"; exit 1; }
APP="$MNT/RedX.app"
[ -d "$APP" ] && ok "RedX.app inside dmg" || bad "no RedX.app"
mkdir -p "$HOME/Applications" && rm -rf "$HOME/Applications/RedX.app" && cp -R "$APP" "$HOME/Applications/" && ok "copied to ~/Applications"
hdiutil detach "$MNT" >/dev/null 2>&1
A="$HOME/Applications/RedX.app"
plutil -lint "$A/Contents/Info.plist" >/dev/null && ok "Info.plist valid"
[ -f "$A/Contents/Resources/redx.icns" ] && ok "icon present" || bad "icon missing"
lipo -info "$A/Contents/MacOS/redxd" | tee /dev/stderr | grep -q "x86_64" && lipo -info "$A/Contents/MacOS/redxd" | grep -q arm64 && ok "universal binary (arm64 + x86_64)" || bad "not universal"
"$A/Contents/MacOS/redxd" --version && ok "redxd runs on $HOSTARCH"
# run the app exactly as double-clicking would (the binary named in Info.plist, no arguments)
export REDX_DATA_DIR="$(mktemp -d)" REDX_LISTEN="127.0.0.1:7791" CI=1
"$A/Contents/MacOS/RedX" >/dev/null 2>&1 &
up=0; for i in $(seq 1 60); do curl -sf http://127.0.0.1:7791/healthz >/dev/null && { up=1; break; }; sleep 0.5; done
[ $up = 1 ] && ok "app launcher started the host (healthz)" || bad "host did not start"
[ "$(curl -s -o /dev/null -w '%{http_code}' http://127.0.0.1:7791/)" = 200 ] && ok "console served" || bad "console"
pkill -x redxd; sleep 1
# pkg
sudo installer -pkg "$PKG" -target / >/dev/null && ok "pkg installs" || bad "pkg install"
[ -d /Applications/RedX.app ] && ok "/Applications/RedX.app" || bad "app not installed by pkg"
/usr/local/bin/redx --version && ok "/usr/local/bin/redx works" || bad "cli from pkg"
# ad-hoc signature present?
codesign -dv /Applications/RedX.app 2>&1 | head -3 || true
rm -rf "$HOME/Applications/RedX.app"
[ $fail = 0 ] && echo "macOS installers verified" || { echo "FAILED"; exit 1; }
