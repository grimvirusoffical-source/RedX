#!/usr/bin/env bash
# Cross-compile redxd + redx for every supported platform (static, CGO off).
# usage: scripts/build.sh [--tags "redx_stub"] [--only linux/amd64,...] [--version X] [--no-archive]
# output: dist/redx-<version>-<os>-<arch>/{redxd,redx,redx-launcher}[.exe], docs, redx.{ico,icns,svg} + dist/*.tar.gz|zip + dist/SHA256SUMS
# (the web console is embedded in redxd itself; scripts/sync-ui-docs.sh is run first so its Help docs match docs/)
# A release build (--version or VERSION=...) refuses a dirty git tree; REDX_ALLOW_DIRTY=1 overrides and stamps "-dirty".
set -euo pipefail
cd "$(dirname "$0")/.."
. scripts/clean-tree.sh

RELEASE=0; [ -n "${VERSION:-}" ] && RELEASE=1
VERSION="${VERSION:-$(git describe --tags --always 2>/dev/null || echo 0.1.0-dev)}"
TAGS="${TAGS:-}"
ONLY=""
ARCHIVE=1
while [ $# -gt 0 ]; do
  case "$1" in
    --tags) TAGS="$2"; shift 2;;
    --only) ONLY="$2"; shift 2;;
    --version) VERSION="$2"; RELEASE=1; shift 2;;
    --no-archive) ARCHIVE=0; shift;;
    *) echo "unknown arg $1" >&2; exit 2;;
  esac
done

# os/arch[/goarm]  (armv7 = Raspberry Pi 2/3/4 32-bit, Termux on 32-bit Android phones)
TARGETS=(linux/amd64 linux/arm64 linux/arm/7 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64)
if [ -n "$ONLY" ]; then
  IFS=',' read -r -a TARGETS <<< "$ONLY"
fi

[ -x scripts/sync-ui-docs.sh ] && scripts/sync-ui-docs.sh >/dev/null
require_clean_tree "$RELEASE"  # after the docs sync: a sync that changed files means the tree was not release-ready
rm -rf dist; mkdir -p dist; FAILED=""
# Windows version resources (icon, version, copyright) are generated for THIS version, never committed
case " ${TARGETS[*]} " in *" windows/"*) scripts/winres.sh "$VERSION" >/dev/null ;; esac
LDFLAGS="-s -w -X redx/host.Version=${VERSION} -X main.version=${VERSION}"  # main.version: redx-launcher
for t in "${TARGETS[@]}"; do
  IFS='/' read -r os arch arm <<< "$t"
  name="${arch}"; [ "$arch" = "arm" ] && name="armv${arm:-7}"
  out="dist/redx-${VERSION}-${os}-${name}"
  ext=""; [ "$os" = "windows" ] && ext=".exe"
  mkdir -p "$out"
  ok=1
  for cmd in redxd redx redx-launcher; do
    echo "build $cmd $os/$name"
    ld="$LDFLAGS"; [ "$os" = windows ] && [ "$cmd" = redx-launcher ] && ld="$LDFLAGS -H=windowsgui"  # no console window
    GOOS=$os GOARCH=$arch GOARM=${arm:-} CGO_ENABLED=0 \
      go build -trimpath -tags "$TAGS" -ldflags "$ld" -o "$out/$cmd$ext" "./cmd/$cmd" || ok=0
  done
  if [ "$ok" = 0 ]; then echo "FAILED target $os/$name (skipped)" >&2; FAILED="$FAILED $os/$name"; rm -rf "$out"; continue; fi
  cp -r deploy/systemd deploy/launchd deploy/windows "$out/" 2>/dev/null || true
  cp docs/hosting.md docs/getting-started.md docs/boxql.md docs/box-grammar.md docs/console.md docs/installers.md docs/connect.md deploy/install.sh deploy/install.ps1 "$out/" 2>/dev/null || true
  # icons: ship the source files so the installers can make menu entries / shortcuts
  cp assets/icons/redx.ico assets/icons/redx.icns assets/icons/redx.svg "$out/" 2>/dev/null || true
  cp deploy/redx.example.toml "$out/redx.example.toml" 2>/dev/null || true
  # the license ships in every archive (LICENSE.txt on Windows so Notepad opens it); a missing LICENSE fails the build
  if [ "$os" = windows ]; then cp LICENSE "$out/LICENSE.txt"; else cp LICENSE "$out/LICENSE"; fi
  if [ "$ARCHIVE" = 1 ]; then
    base="$(basename "$out")"
    if [ "$os" = "windows" ] && command -v zip >/dev/null; then
      (cd dist && zip -qr "$base.zip" "$base")
    elif [ "$os" = "windows" ] && command -v python3 >/dev/null; then
      (cd dist && python3 -m zipfile -c "$base.zip" "$base")
    else
      tar -C dist -czf "dist/$base.tar.gz" "$base"
    fi
  fi
done
(cd dist && { ls *.tar.gz *.zip 2>/dev/null | xargs -r sha256sum; } > SHA256SUMS || true)
echo "done: dist/"
if [ -n "${FAILED:-}" ]; then echo "failed targets:$FAILED" >&2; exit 1; fi
