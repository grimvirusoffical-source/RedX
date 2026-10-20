#!/bin/sh
# RedX host uninstaller for Linux and macOS: undoes deploy/install.sh. Same mode flags as install.sh.
#
#   ./uninstall.sh --user                 # rootless install: ~/.local/bin, launcher; keeps ~/.redx
#   sudo ./uninstall.sh                   # system install: systemd (Linux) / launchd (macOS); keeps data + config
#   sudo ./uninstall.sh --purge           # ALSO deletes data, config and logs (databases and keys are lost!)
#   sudo ./uninstall.sh --purge --remove-user   # ...and the 'redx' system user (Linux)
#   --prefix DIR   same --prefix that was given to install.sh (default /usr/local)
#
# Idempotent: anything already gone is skipped, so it is safe on a partial install and safe to run twice.
set -eu

PREFIX=/usr/local; USERMODE=0; PURGE=0; RMUSER=0
while [ $# -gt 0 ]; do
  case "$1" in
    --prefix) PREFIX="$2"; shift 2;;
    --user) USERMODE=1; shift;;
    --purge) PURGE=1; shift;;
    --remove-user) RMUSER=1; shift;;
    -h|--help) sed -n '2,11p' "$0"; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done
[ "$RMUSER" = 0 ] || [ "$PURGE" = 1 ] || { echo "--remove-user requires --purge" >&2; exit 2; }
OS=$(uname -s | tr '[:upper:]' '[:lower:]')
case "$OS" in linux|darwin) ;; *) echo "unsupported OS: $OS (use install.ps1 -Uninstall on Windows)" >&2; exit 1;; esac

rmf() { for f in "$@"; do if [ -e "$f" ] || [ -L "$f" ]; then rm -f -- "$f"; echo "removed $f"; fi; done; }
rmd() { for d in "$@"; do if [ -d "$d" ]; then rm -rf -- "$d"; echo "removed $d"; fi; done; }
rm_bins() { rmf "$1/redxd" "$1/redx" "$1/redx-launcher"; }

if [ "$USERMODE" = 1 ]; then
  [ -n "${HOME:-}" ] && [ "$HOME" != / ] || { echo "HOME is not set" >&2; exit 1; }
  # a foreground 'redxd run' started from ~/.local/bin is stopped so files are not held open
  if command -v pkill >/dev/null 2>&1; then pkill -u "$(id -u)" -f "^$HOME/.local/bin/redxd run" 2>/dev/null || true; fi
  rm_bins "$HOME/.local/bin"
  if [ "$OS" = linux ]; then
    rmf "$HOME/.local/share/applications/redx-console.desktop" "$HOME/.local/share/icons/hicolor/scalable/apps/redx.svg"
  else
    rmd "$HOME/Applications/RedX Console.app"
  fi
  if [ "$PURGE" = 1 ]; then rmd "$HOME/.redx"; else [ -d "$HOME/.redx" ] && echo "kept data and config in $HOME/.redx (use --purge to delete)"; fi
  echo "RedX (user install) uninstalled."
  exit 0
fi

[ "$(id -u)" = 0 ] || { echo "run as root (sudo), or use --user" >&2; exit 1; }
BIN="$PREFIX/bin"
if [ "$OS" = linux ]; then
  U=/etc/systemd/system/redxd.service
  if command -v systemctl >/dev/null 2>&1 && [ -d /run/systemd/system ]; then
    systemctl disable --now redxd >/dev/null 2>&1 && echo "stopped and disabled redxd" || true
  fi
  rmf "$U"
  command -v systemctl >/dev/null 2>&1 && { systemctl daemon-reload >/dev/null 2>&1 || true; systemctl reset-failed redxd >/dev/null 2>&1 || true; }
  # a manually started 'redxd run' (no-systemd hosts) is stopped too
  command -v pkill >/dev/null 2>&1 && pkill -f "^$BIN/redxd run --config /etc/redx/redx.toml" 2>/dev/null || true
  rm_bins "$BIN"
  rmf /usr/share/applications/redx-console.desktop /usr/share/icons/hicolor/scalable/apps/redx.svg
  if [ "$PURGE" = 1 ]; then
    rmd /var/lib/redx /etc/redx
    if [ "$RMUSER" = 1 ] && id redx >/dev/null 2>&1; then
      userdel redx 2>/dev/null || deluser --system redx >/dev/null 2>&1 || true
      getent group redx >/dev/null 2>&1 && { groupdel redx 2>/dev/null || true; }
      id redx >/dev/null 2>&1 && echo "could not remove user redx" >&2 || echo "removed system user redx"
    fi
  else
    echo "kept data (/var/lib/redx), config (/etc/redx) and user redx (use --purge [--remove-user] to delete)"
  fi
else
  P=/Library/LaunchDaemons/com.redx.redxd.plist
  if [ -f "$P" ]; then launchctl unload -w "$P" 2>/dev/null || true; echo "unloaded com.redx.redxd"; fi
  launchctl remove com.redx.redxd 2>/dev/null || true
  rmf "$P"
  rm_bins "$BIN"
  rmd "/Applications/RedX Console.app"
  if [ "$PURGE" = 1 ]; then
    rmd /usr/local/var/redx /usr/local/etc/redx; rmf /usr/local/var/log/redxd.log
  else
    echo "kept data (/usr/local/var/redx) and config (/usr/local/etc/redx) (use --purge to delete)"
  fi
fi
echo "RedX uninstalled."
