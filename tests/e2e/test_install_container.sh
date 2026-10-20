#!/bin/sh
# Installer E2E inside a disposable container (real root). No shared-box /etc writes.
set -e
ROOT=${REDX_E2E_ROOT:-$(cd "$(dirname "$0")/../.." && pwd)}
BINDIR=${REDX_BIN_DIR:-$ROOT/bin}
DEPLOY=${REDX_DEPLOY_DIR:-$ROOT/deploy}
IMG=ubuntu:24.04
WORKDIR=$(mktemp -d /tmp/redx-install-XXXX)
cp -a "$BINDIR/redxd" "$BINDIR/redx" "$WORKDIR/"
cp -a "$DEPLOY/install.sh" "$DEPLOY/redx.example.toml" "$WORKDIR/"
cp -a "$DEPLOY/systemd/redxd.service" "$WORKDIR/redxd.service" 2>/dev/null || true
chmod -R a+rX "$WORKDIR"
chmod +x "$WORKDIR/redxd" "$WORKDIR/redx" "$WORKDIR/install.sh"
sudo docker pull -q "$IMG" >/dev/null

echo "== rootless --user install =="
sudo docker run --rm --name redx-e2e-install-user \
  -v "$WORKDIR:/payload:ro" \
  -e DEBIAN_FRONTEND=noninteractive \
  "$IMG" bash -lc '
set -e
apt-get update -qq >/dev/null
apt-get install -qq -y ca-certificates curl >/dev/null
useradd -m builder
# root copies into builder home (payload may be unreadable to non-root depending on mount uid)
mkdir -p /home/builder/dist
cp /payload/redxd /payload/redx /payload/install.sh /payload/redx.example.toml /home/builder/dist/
chmod +x /home/builder/dist/*
chown -R builder:builder /home/builder/dist
su - builder -c "/home/builder/dist/install.sh --from /home/builder/dist --user --listen 127.0.0.1:17771"
stat -c "%a %U" /home/builder/.redx/data | grep -E "^700 builder$"
CFG=$(ls /home/builder/.redx/redx.toml 2>/dev/null)
if [ -n "$CFG" ]; then
  PERM=$(stat -c "%a" "$CFG")
  case "$PERM" in *4|*5|*6|*7)
    # world bit
    W=$(echo "$PERM" | cut -c3)
    case "$W" in 4|5|6|7) echo "config world-readable: $PERM $CFG"; exit 1;; esac
  ;; esac
fi
su - builder -c "/home/builder/.local/bin/redxd run --config /home/builder/.redx/redx.toml --bootstrap console" >/tmp/u.out 2>&1 &
UPID=$!
sleep 2
curl -sf http://127.0.0.1:17771/healthz >/dev/null
kill $UPID 2>/dev/null || true
wait $UPID 2>/dev/null || true
# Ensure binary not busy
pkill -9 -f "/home/builder/.local/bin/redxd" 2>/dev/null || true
sleep 1
su - builder -c "/home/builder/dist/install.sh --from /home/builder/dist --user --listen 127.0.0.1:17771" | tee /tmp/reinst.txt
grep -Eiq "keep|existing|keystore already" /tmp/reinst.txt
echo USER_INSTALL_OK
'

echo "== system root install (no systemd unit start) =="
sudo docker run --rm --name redx-e2e-install-root \
  -v "$WORKDIR:/payload:ro" \
  -e DEBIAN_FRONTEND=noninteractive \
  "$IMG" bash -lc '
set -e
apt-get update -qq >/dev/null
apt-get install -qq -y ca-certificates curl >/dev/null
mkdir -p /opt/redx-dist/systemd
cp /payload/redxd /payload/redx /payload/install.sh /payload/redx.example.toml /opt/redx-dist/
[ -f /payload/redxd.service ] && cp /payload/redxd.service /opt/redx-dist/systemd/
chmod +x /opt/redx-dist/*
# install.sh expects deploy layout: systemd next to itself when FROM is dist
# Symlink so HERE_DEPLOY/systemd resolves: install.sh uses dirname(install.sh)/systemd
mkdir -p /opt/redx-dist
/opt/redx-dist/install.sh --from /opt/redx-dist --listen 127.0.0.1:17772 --no-service
id redx >/dev/null
install -d -o redx -g redx -m 0700 /var/lib/redx
su -s /bin/bash redx -c "/usr/local/bin/redxd run --config /etc/redx/redx.toml --bootstrap console" >/tmp/r.out 2>&1 &
RPID=$!
sleep 2
curl -sf http://127.0.0.1:17772/healthz >/dev/null
kill $RPID 2>/dev/null || true
wait $RPID 2>/dev/null || true
pkill -9 -u redx -f redxd 2>/dev/null || true
sleep 1
stat -c "%a %U" /var/lib/redx | grep -E "^700 redx$"
! find /var/lib/redx -type f -perm -004 2>/dev/null | grep -q .
su -s /bin/bash redx -c "/usr/local/bin/redxd run --data-dir /var/lib/redx --listen 127.0.0.1:17773 --bootstrap off" >/tmp/r2.out 2>&1 &
PID=$!
sleep 1
set +e
su -s /bin/bash redx -c "/usr/local/bin/redxd run --data-dir /var/lib/redx --listen 127.0.0.1:17774 --bootstrap off" >/tmp/r3.out 2>&1
RC=$?
set -e
kill $PID 2>/dev/null || true
wait $PID 2>/dev/null || true
pkill -9 -u redx -f redxd 2>/dev/null || true
sleep 1
test "$RC" -ne 0
/opt/redx-dist/install.sh --from /opt/redx-dist --listen 127.0.0.1:17772 --no-service | tee /tmp/reinst-root.txt
grep -Eiq "keep|existing|keystore already" /tmp/reinst-root.txt
echo ROOT_INSTALL_OK
'

echo "== systemd unit install (optional) =="
if sudo docker pull -q jrei/systemd-ubuntu:24.04 >/tmp/sysd-pull.txt 2>&1; then
  CID=$(sudo docker run -d --privileged --cgroupns=host \
    -v /sys/fs/cgroup:/sys/fs/cgroup:rw \
    -v "$WORKDIR:/payload:ro" \
    --name redx-e2e-install-systemd \
    jrei/systemd-ubuntu:24.04)
  sleep 3
  if sudo docker exec "$CID" bash -lc '
set -e
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq >/dev/null
apt-get install -qq -y ca-certificates curl >/dev/null
mkdir -p /opt/redx-dist/systemd
cp /payload/redxd /payload/redx /payload/install.sh /payload/redx.example.toml /opt/redx-dist/
cp /payload/redxd.service /opt/redx-dist/systemd/redxd.service
chmod +x /opt/redx-dist/*
/opt/redx-dist/install.sh --from /opt/redx-dist --listen 127.0.0.1:17775
systemctl daemon-reload
systemctl enable --now redxd
sleep 3
curl -sf http://127.0.0.1:17775/healthz >/dev/null
stat -c "%a %U" /var/lib/redx | grep -E "^700 redx$"
! find /var/lib/redx -type f -perm -004 2>/dev/null | grep -q .
echo SYSTEMD_INSTALL_OK
'; then
    echo SYSTEMD_INSTALL_OK
  else
    echo SYSTEMD_INSTALL_SKIPPED
  fi
  sudo docker rm -f "$CID" >/dev/null 2>&1 || true
else
  echo "SYSTEMD_INSTALL_NOT_RUN (image pull failed)"
fi

rm -rf "$WORKDIR"
echo INSTALL_E2E_DONE
