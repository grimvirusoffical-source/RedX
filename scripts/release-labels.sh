#!/usr/bin/env bash
# GitHub release asset labels (contract §5, all releases from 0.4.5). Filenames never change; only the label.
#   scripts/release-labels.sh VERSION FILE...   -> prints "<file>\t<label>" per file; unknown file = exit 1
# Every platform ships two or more kinds, so every label carries its kind suffix.
set -euo pipefail
VERSION="${1:?usage: release-labels.sh VERSION FILE...}"; shift
label() {
  local f; f="$(basename "$1")"
  [ "$f" = SHA256SUMS ] && { echo "RedX $VERSION checksums (SHA256SUMS)"; return; }
  local plat="" kind=""
  case "$f" in
    *-darwin-arm64.*|*-macos-arm64.*)       plat="Mac, M1 chip" ;;
    *-darwin-amd64.*|*-macos-amd64.*)       plat="Mac, Intel chip" ;;
    *-macos-universal.*)                    plat="Mac, Universal" ;;
    *-windows-amd64*)                       plat="Windows" ;;
    *-windows-arm64*)                       plat="Windows, ARM" ;;
    *-linux-amd64.*|redx_*_amd64.deb)       plat="Linux" ;;
    *-linux-arm64.*|redx_*_arm64.deb)       plat="Linux, ARM64" ;;
    *-linux-armv7.*|redx_*_armhf.deb)       plat="Linux, Raspberry Pi" ;;
  esac
  case "$f" in
    *.dmg)     kind="Disk image (.dmg)" ;;
    *.pkg)     kind="Installer (.pkg)" ;;
    *.tar.gz)  kind="Archive (.tar.gz)" ;;
    *-setup.exe) kind="Installer (.exe)" ;;
    *.zip)     kind="Portable (.zip)" ;;
    *.deb)     kind="Debian package (.deb)" ;;
  esac
  [ -n "$plat" ] && [ -n "$kind" ] || { echo "release-labels: no label rule for $f" >&2; return 1; }
  echo "RedX $VERSION ($plat) — $kind"
}
for f in "$@"; do printf '%s\t%s\n' "$(basename "$f")" "$(label "$f")"; done
