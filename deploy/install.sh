#!/bin/sh
# RedX host installer for Linux and macOS. Installs from a LOCAL build directory (nothing is downloaded).
#
#   sudo ./install.sh --from dist/redx-<ver>-linux-amd64      # system service (systemd / launchd)
#   ./install.sh --from dist --user                           # no root: ~/.local/bin + ~/.redx, no service
#   ./install.sh --from dist --listen 0.0.0.0:7777 --tls auto # reachable from other devices, with TLS
#
#   ./install.sh --from dist --tls files --tls-cert /etc/redx/c.pem --tls-key /etc/redx/k.pem
#   Undo with deploy/uninstall.sh (same mode flags; data/config kept unless --purge).
# --from may be the directory holding redxd+redx, or the dist/ root (the right redx-*-OS-ARCH folder is picked).
set -eu

FROM=""; PREFIX=/usr/local; LISTEN="127.0.0.1:7777"; TLS="off"; USERMODE=0; NOSVC=0; ROLE=leader; PEERS=""; TLSCERT=""; TLSKEY=""
while [ $# -gt 0 ]; do
  case "$1" in
    --from) FROM="$2"; shift 2;;
    --prefix) PREFIX="$2"; shift 2;;
    --listen) LISTEN="$2"; shift 2;;
    --tls) TLS="$2"; shift 2;;
    --role) ROLE="$2"; shift 2;;
    --peers) PEERS="$2"; shift 2;;
    --tls-cert) TLSCERT="$2"; shift 2;;
    --tls-key) TLSKEY="$2"; shift 2;;
    --user) USERMODE=1; NOSVC=1; shift;;
    --no-service) NOSVC=1; shift;;
    -h|--help) sed -n '2,12p' "$0"; exit 0;;
    *) echo "unknown option: $1" >&2; exit 2;;
  esac
done

# --- TOML string safety: every user value written to redx.toml goes through toml_str ----------------
NL='
'
# reject_ctl NAME VALUE: refuse newlines and any other control character (C0 and DEL)
reject_ctl() {
  case "$2" in *"$NL"*) echo "invalid $1: newlines are not allowed" >&2; exit 2;; esac
  if printf '%s' "$2" | LC_ALL=C grep -q '[[:cntrl:]]'; then echo "invalid $1: control characters are not allowed" >&2; exit 2; fi
}
# toml_str VALUE -> "VALUE" as a TOML basic string (backslash and double quote escaped)
toml_str() { printf '"%s"' "$(printf '%s' "$1" | sed -e 's/\\/\\\\/g' -e 's/"/\\"/g')"; }
reject_ctl --listen "$LISTEN"; reject_ctl --tls "$TLS"; reject_ctl --role "$ROLE"; reject_ctl --peers "$PEERS"
reject_ctl --tls-cert "$TLSCERT"; reject_ctl --tls-key "$TLSKEY"; reject_ctl HOME "${HOME:-}"

OS=$(uname -s | tr '[:upper:]' '[:lower:]'); M=$(uname -m)
case "$M" in
  x86_64|amd64) ARCH=amd64;; aarch64|arm64) ARCH=arm64;; armv7*|armv6*|armhf) ARCH=armv7;;
  *) echo "unsupported CPU: $M" >&2; exit 1;;
esac
case "$OS" in linux|darwin) ;; *) echo "unsupported OS: $OS (use install.ps1 on Windows)" >&2; exit 1;; esac

[ -n "$FROM" ] || { HERE=$(cd "$(dirname "$0")" && pwd); FROM="$HERE"; [ -x "$FROM/redxd" ] || FROM="$HERE/../dist"; }
if [ ! -x "$FROM/redxd" ]; then
  CAND=$(ls -d "$FROM"/redx-*-"$OS"-"$ARCH" 2>/dev/null | head -n1 || true)
  [ -n "$CAND" ] && FROM="$CAND"
fi
[ -x "$FROM/redxd" ] && [ -x "$FROM/redx" ] || { echo "redxd/redx not found in $FROM (build first: make dist)" >&2; exit 1; }
echo "installing $OS/$ARCH binaries from $FROM"

HERE_DEPLOY=$(cd "$(dirname "$0")" && pwd)
EXAMPLE="$HERE_DEPLOY/redx.example.toml"; [ -f "$EXAMPLE" ] || EXAMPLE="$FROM/redx.example.toml"

write_conf() { # $1=path $2=data_dir
  mkdir -p "$(dirname "$1")"
  if [ -e "$1" ]; then echo "keeping existing config $1"; return; fi
  {
    printf '%s = %s\n' data_dir "$(toml_str "$2")"
    printf '%s = %s\n' listen "$(toml_str "$LISTEN")"
    printf '%s = %s\n' tls "$(toml_str "$TLS")"
    [ -z "$TLSCERT" ] || printf '%s = %s\n' tls_cert "$(toml_str "$TLSCERT")"
    [ -z "$TLSKEY" ] || printf '%s = %s\n' tls_key "$(toml_str "$TLSKEY")"
    printf '%s = %s\n' role "$(toml_str "$ROLE")"
    if [ -n "$PEERS" ]; then # --peers a,b,c -> peers = ["a", "b", "c"]
      printf 'peers = ['; SEP=""; OLDIFS=$IFS; IFS=,; set -f
      for P in $PEERS; do [ -n "$P" ] && printf '%s%s' "$SEP" "$(toml_str "$P")" && SEP=", "; done
      set +f; IFS=$OLDIFS; echo "]"
    fi
  } > "$1"
  chmod 640 "$1" 2>/dev/null || true
}

# URL a browser on THIS machine uses for the web console (0.0.0.0 / empty host -> 127.0.0.1)
console_url() {
  SCHEME=http; [ "$TLS" = off ] || SCHEME=https
  PORT="${LISTEN##*:}"; H="${LISTEN%:*}"
  case "$H" in ""|0.0.0.0|"::"|"[::]") H=127.0.0.1;; esac
  echo "$SCHEME://$H:$PORT/"
}

# Optional launcher so the console can be opened from the app menu / Launchpad. Best effort, never fatal.
# $1 = "user" or "system". Needs redx.svg / redx.icns next to the binaries (the release archives ship them).
install_launcher() {
  URL=$(console_url)
  # the URL comes from --listen; only write launchers for a plain URL (no shell/desktop-entry metacharacters)
  case "$URL" in *[!A-Za-z0-9:/.\[\]_-]*) echo "skipping console launcher (unusual --listen value)"; return 0;; esac
  if [ "$OS" = linux ]; then
    if [ "$1" = user ]; then APPS="${HOME}/.local/share/applications"; ICONS="${HOME}/.local/share/icons/hicolor/scalable/apps"
    else APPS=/usr/share/applications; ICONS=/usr/share/icons/hicolor/scalable/apps; fi
    mkdir -p "$APPS" "$ICONS" 2>/dev/null || return 0
    OPEN_CMD="xdg-open $URL"; [ -x "$BIN/redx-launcher" ] && OPEN_CMD="$BIN/redx-launcher"  # starts the host if it is not running
    [ -f "$FROM/redx.svg" ] && cp "$FROM/redx.svg" "$ICONS/redx.svg" 2>/dev/null || true
    cat > "$APPS/redx-console.desktop" <<EOF2 2>/dev/null || return 0
[Desktop Entry]
Type=Application
Name=RedX Console
Comment=Open the RedX web console in your browser
Exec=$OPEN_CMD
Icon=redx
Terminal=false
Categories=Development;Database;
EOF2
    echo "added a 'RedX Console' launcher to the application menu"
  else
    APPDIR=/Applications; [ "$1" = user ] && APPDIR="${HOME}/Applications"
    APP="$APPDIR/RedX Console.app"
    mkdir -p "$APP/Contents/MacOS" "$APP/Contents/Resources" 2>/dev/null || return 0
    [ -f "$FROM/redx.icns" ] && cp "$FROM/redx.icns" "$APP/Contents/Resources/redx.icns" 2>/dev/null || true
    cat > "$APP/Contents/Info.plist" <<EOF2
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict>
<key>CFBundleName</key><string>RedX Console</string>
<key>CFBundleIdentifier</key><string>com.redx.console</string>
<key>CFBundleExecutable</key><string>redx-console</string>
<key>CFBundleIconFile</key><string>redx</string>
<key>CFBundlePackageType</key><string>APPL</string>
<key>CFBundleShortVersionString</key><string>1.0</string>
<key>LSUIElement</key><true/>
</dict></plist>
EOF2
    printf '#!/bin/sh\nexec /usr/bin/open "%s"\n' "$URL" > "$APP/Contents/MacOS/redx-console"
    chmod 755 "$APP/Contents/MacOS/redx-console"
    echo "added '$APP' (opens the console in your browser)"
  fi
}

make_admin_key() { # $1=data dir ; remaining: command prefix (e.g. runuser -u redx --)
  D="$1"; shift
  if [ "$ROLE" = follower ]; then echo "follower node: keys come from the leader; skipping admin key"; return; fi
  if [ -e "$D/keys.red-xai-keys" ]; then echo "keystore already exists; not creating another admin key"; return; fi
  echo
  echo "==== Creating the first ADMIN API key (shown once, never stored in clear) ===="
  "$@" "$BIN/redx" key create --offline --data-dir "$D" --scope admin --db '*' --label bootstrap-admin
  echo "================================================================================"
}

if [ "$USERMODE" = 1 ]; then
  BIN="${HOME}/.local/bin"; DATA="${HOME}/.redx/data"; CONF="${HOME}/.redx/redx.toml"
  mkdir -p "$BIN" "$DATA"; chmod 700 "$DATA"
  cp "$FROM/redxd" "$FROM/redx" "$BIN/"
  [ -f "$FROM/redx-launcher" ] && cp "$FROM/redx-launcher" "$BIN/"
  write_conf "$CONF" "$DATA"
  make_admin_key "$DATA"
  install_launcher user || true
  echo "installed to $BIN. Start the host with:"
  echo "   $BIN/redxd run --config $CONF"
  echo
  echo "Then open the web console:  $(console_url)     (or run:  $BIN/redxd open --config $CONF)"
  echo "Everything - databases, data, queries, keys, devices, backups - can be done there; the terminal is optional."
  case ":$PATH:" in *":$BIN:"*) ;; *) echo "(add $BIN to your PATH)";; esac
  exit 0
fi

[ "$(id -u)" = 0 ] || { echo "run as root (sudo), or use --user" >&2; exit 1; }
BIN="$PREFIX/bin"
install -d "$BIN"
install -m 0755 "$FROM/redxd" "$FROM/redx" "$BIN/"
[ -f "$FROM/redx-launcher" ] && install -m 0755 "$FROM/redx-launcher" "$BIN/"

if [ "$OS" = linux ]; then
  DATA=/var/lib/redx; CONF=/etc/redx/redx.toml
  id redx >/dev/null 2>&1 || useradd --system --home-dir "$DATA" --shell /usr/sbin/nologin redx 2>/dev/null || adduser --system --home "$DATA" --shell /usr/sbin/nologin redx
  install -d -m 0700 -o redx -g redx "$DATA"
  write_conf "$CONF" "$DATA"; chgrp redx "$CONF" 2>/dev/null || true
  if command -v runuser >/dev/null; then RUN="runuser -u redx --"; elif command -v sudo >/dev/null; then RUN="sudo -u redx"; else RUN=""; fi
  make_admin_key "$DATA" $RUN
  [ -z "$RUN" ] || true
  chown -R redx:redx "$DATA"
  if [ "$NOSVC" = 0 ] && command -v systemctl >/dev/null; then
    UNIT_SRC="$HERE_DEPLOY/systemd/redxd.service"; [ -f "$UNIT_SRC" ] || UNIT_SRC="$FROM/systemd/redxd.service"
    # render the single unit template (deploy/systemd/redxd.service); the bin dir must be unit-safe
    case "$BIN" in *[!A-Za-z0-9/._-]*) echo "--prefix must contain only A-Z a-z 0-9 / . _ - for the systemd unit" >&2; exit 2;; esac
    sed -e "s#@BINDIR@#$BIN#g" -e "s#@DOCDIR@#$PREFIX/share/doc/redx#g" "$UNIT_SRC" > /etc/systemd/system/redxd.service
    chmod 0644 /etc/systemd/system/redxd.service
    systemctl daemon-reload
    if [ "$ROLE" = follower ]; then
      systemctl enable redxd
      echo "follower: service installed but NOT started. Join first, then start:"
      echo "   redx node join <leader-url> --token <rxj_...> --pin <fingerprint> --advertise <this-url> --data-dir $DATA"
      echo "   chown -R redx:redx $DATA && systemctl start redxd"
    else
      systemctl enable --now redxd
      sleep 1; systemctl --no-pager --lines=5 status redxd || true
    fi
  else
    echo "no systemd (or --no-service): run manually:  sudo -u redx $BIN/redxd run --config $CONF"
  fi
else
  DATA=/usr/local/var/redx; CONF=/usr/local/etc/redx/redx.toml
  install -d -m 0700 "$DATA" /usr/local/var/log
  write_conf "$CONF" "$DATA"
  make_admin_key "$DATA"
  if [ "$NOSVC" = 0 ]; then
    P=/Library/LaunchDaemons/com.redx.redxd.plist
    install -m 0644 "$HERE_DEPLOY/launchd/com.redx.redxd.plist" "$P" 2>/dev/null || install -m 0644 "$FROM/launchd/com.redx.redxd.plist" "$P"
    sed -i '' "s#/usr/local/bin#$BIN#g" "$P"
    launchctl unload "$P" 2>/dev/null || true
    if [ "$ROLE" = follower ]; then
      echo "follower: launchd plist installed but not loaded. Run 'redx node join ...' then: sudo launchctl load -w $P"
    else
      launchctl load -w "$P"
      echo "launchd service com.redx.redxd loaded (runs as root; log: /usr/local/var/log/redxd.log)"
    fi
  fi
fi
install_launcher system || true
echo
echo "Open the web console in your browser:  $(console_url)"
echo "  (everything can be done there; the terminal is optional. Paste the admin key above to sign in.)"
echo
echo "Done. Check:  REDX_KEY=<your admin key> redx doctor     and     curl http://127.0.0.1:7777/healthz"
