#!/bin/sh
# Create one unprivileged login for a RedX tenant app. Installed as root at
# /usr/local/sbin/redx-app-user. redxd invokes it with: sudo -n /usr/local/sbin/redx-app-user USER UID
set -eu
if [ "$(id -u)" -ne 0 ]; then
  echo "redx-app-user must run as root" >&2
  exit 1
fi
user=${1:-}
uid=${2:-}
case "$user" in
  rxapp-[0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f][0-9a-f]) ;;
  *) echo "user must look like rxapp- plus 10 hex characters" >&2; exit 1 ;;
esac
case "$uid" in
  ''|*[!0-9]*) echo "uid must be a number" >&2; exit 1 ;;
esac
if [ "$uid" -lt 200000 ] || [ "$uid" -gt 219999 ]; then
  echo "uid $uid is outside 200000-219999" >&2
  exit 1
fi
if id "$user" >/dev/null 2>&1; then
  exit 0
fi
home=/var/lib/redx/hosted/uids/$user
install -d -m 0750 -o root -g root /var/lib/redx/hosted/uids
if ! getent group "$uid" >/dev/null 2>&1; then
  groupadd --system --gid "$uid" "$user"
fi
useradd --system --uid "$uid" --gid "$uid" --home-dir "$home" --create-home --shell /usr/sbin/nologin "$user"
chmod 0700 "$home"
stamp=/var/lib/redx/hosted/subuid-next
if [ ! -f "$stamp" ]; then
  echo 1000000 >"$stamp"
  chmod 0600 "$stamp"
fi
start=$(cat "$stamp")
next=$((start + 65536))
echo "$next" >"$stamp"
grep -q "^$user:" /etc/subuid || echo "$user:$start:65536" >>/etc/subuid
grep -q "^$user:" /etc/subgid || echo "$user:$start:65536" >>/etc/subgid
loginctl enable-linger "$user" || true
install -d -m 0700 -o "$user" -g "$user" /run/user/"$uid"
exit 0
