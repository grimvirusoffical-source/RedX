#!/usr/bin/env bash
# Build redx_<ver>_<debarch>.deb from already-built binaries.
# usage: build-deb.sh VERSION GOARCH BINDIR OUTDIR     (GOARCH: amd64|arm64|armv7)
set -euo pipefail
VERSION="$1"; GA="$2"; BIN="$3"; OUT="$4"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
case "$GA" in amd64) DA=amd64;; arm64) DA=arm64;; armv7) DA=armhf;; *) echo "bad arch" >&2; exit 2;; esac
W="$(mktemp -d)"; P="$W/pkg"
install -d "$P/DEBIAN" "$P/usr/bin" "$P/usr/share/applications" "$P/usr/share/icons/hicolor/256x256/apps" \
  "$P/usr/share/icons/hicolor/scalable/apps" "$P/lib/systemd/system" "$P/usr/share/doc/redx"
install -m 0755 "$BIN/redxd" "$BIN/redx" "$BIN/redx-launcher" "$P/usr/bin/"
install -m 0644 "$ROOT/deploy/linux/redx.desktop" "$P/usr/share/applications/redx.desktop"
install -m 0644 "$ROOT/assets/icons/png/redx-256.png" "$P/usr/share/icons/hicolor/256x256/apps/redx.png"
install -m 0644 "$ROOT/assets/icons/redx.svg" "$P/usr/share/icons/hicolor/scalable/apps/redx.svg"
install -m 0644 "$ROOT/deploy/linux/redxd.service" "$P/lib/systemd/system/redxd.service"
for d in hosting.md getting-started.md boxql.md box-grammar.md console.md installers.md connect.md; do [ -f "$ROOT/docs/$d" ] && install -m 0644 "$ROOT/docs/$d" "$P/usr/share/doc/redx/$d"; done
install -m 0644 "$ROOT/deploy/redx.example.toml" "$P/usr/share/doc/redx/redx.example.toml"
SIZE=$(du -sk "$P" | cut -f1)
cat > "$P/DEBIAN/control" <<CTL
Package: redx
Version: ${VERSION}
Section: database
Priority: optional
Architecture: ${DA}
Maintainer: RedX <support@infected-nation.com>
Installed-Size: ${SIZE}
Description: RedX database host and CLI
 Multi-file-type database host with the Box data model, BoxQL, and a web console.
 Start "RedX" from your application menu (or run redx-launcher): it starts a private
 host in your home directory and opens the web console. To run it as a system service
 instead: sudo systemctl enable --now redxd   (see /usr/share/doc/redx/hosting.md).
CTL
cat > "$P/DEBIAN/postinst" <<'PI'
#!/bin/sh
set -e
if [ "$1" = configure ]; then
  id redx >/dev/null 2>&1 || adduser --system --group --home /var/lib/redx --no-create-home --shell /usr/sbin/nologin redx >/dev/null 2>&1 || true
  install -d -m 0700 -o redx -g redx /var/lib/redx 2>/dev/null || true
  if [ ! -e /etc/redx/redx.toml ]; then
    install -d -m 0755 /etc/redx
    printf 'data_dir = "/var/lib/redx"\nlisten = "127.0.0.1:7777"\ntls = "off"\nrole = "leader"\n' > /etc/redx/redx.toml
    chmod 0640 /etc/redx/redx.toml; chgrp redx /etc/redx/redx.toml 2>/dev/null || true
  fi
  command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload >/dev/null 2>&1 || true
  echo "RedX installed. Launch it from your application menu, or run it as a service:"
  echo "  sudo systemctl enable --now redxd   (then create the admin key: sudo -u redx redx key create --offline --data-dir /var/lib/redx --scope admin --db '*' --label admin)"
fi
exit 0
PI
cat > "$P/DEBIAN/prerm" <<'PR'
#!/bin/sh
set -e
if [ "$1" = remove ] && command -v systemctl >/dev/null 2>&1; then systemctl stop redxd >/dev/null 2>&1 || true; systemctl disable redxd >/dev/null 2>&1 || true; fi
exit 0
PR
chmod 0755 "$P/DEBIAN/postinst" "$P/DEBIAN/prerm"
mkdir -p "$OUT"
dpkg-deb --root-owner-group --build "$P" "$OUT/redx_${VERSION}_${DA}.deb" >/dev/null
rm -rf "$W"; echo "built $OUT/redx_${VERSION}_${DA}.deb"
