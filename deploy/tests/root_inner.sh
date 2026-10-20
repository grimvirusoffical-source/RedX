#!/bin/sh
# Runs as root INSIDE the disposable systemd container started by root_docker_test.sh. Do not run on a host.
set -u
[ -f /.dockerenv ] || { echo "refusing: not inside a container" >&2; exit 1; }
I=/src/deploy/install.sh; U=/src/deploy/uninstall.sh; F=/bin-in; UNIT=/etc/systemd/system/redxd.service
FAILS=0; fail() { echo "FAIL $*"; FAILS=$((FAILS+1)); }; ok() { echo "ok   $*"; }
healthy() { for i in $(seq 50); do curl -fsS http://127.0.0.1:7777/healthz >/dev/null 2>&1 && return 0; sleep 0.2; done; return 1; }

# 1. root install with systemd
sh $I --from $F >/tmp/i1.log 2>&1 || { fail "install: $(cat /tmp/i1.log)"; }
grep -q '^ExecStart=/usr/local/bin/redxd run --config /etc/redx/redx.toml --no-open$' $UNIT && ok "unit rendered for /usr/local/bin" || fail "unit ExecStart: $(grep ExecStart $UNIT)"
grep -q '@[A-Z]*@' $UNIT && fail "unrendered placeholder in unit"
for h in NoNewPrivileges=true ProtectSystem=strict ProtectHome=true PrivateTmp=true PrivateDevices=true ReadWritePaths=/var/lib/redx REDX_NO_BOOTSTRAP=1; do grep -q "$h" $UNIT || fail "hardening missing: $h"; done
systemd-analyze verify $UNIT >/tmp/verify.log 2>&1 || fail "systemd-analyze verify: $(cat /tmp/verify.log)"
[ "$(systemctl is-enabled redxd)" = enabled ] && ok "enabled" || fail "not enabled"
[ "$(systemctl is-active redxd)" = active ] && healthy && ok "active + /healthz" || fail "service not healthy: $(journalctl -u redxd --no-pager -n 20)"
[ "$(stat -c %U:%a /var/lib/redx)" = redx:700 ] || fail "data dir owner/perms $(stat -c %U:%a /var/lib/redx)"
SUM=$(sha256sum /etc/redx/redx.toml /var/lib/redx/keys.red-xai-keys)

# 2. uninstall keeps data/config/user; idempotent
sh $U >/tmp/u1.log 2>&1 || fail "uninstall: $(cat /tmp/u1.log)"
systemctl is-active -q redxd && fail "still active after uninstall"
[ -e $UNIT ] && fail "unit left"; systemctl cat redxd >/dev/null 2>&1 && fail "systemd still knows redxd"
for f in /usr/local/bin/redxd /usr/local/bin/redx /usr/local/bin/redx-launcher /usr/share/applications/redx-console.desktop; do [ -e $f ] && fail "left $f"; done
curl -fsS http://127.0.0.1:7777/healthz >/dev/null 2>&1 && fail "port still served"
[ "$(sha256sum /etc/redx/redx.toml /var/lib/redx/keys.red-xai-keys)" = "$SUM" ] && ok "data+config kept" || fail "data/config changed"
id redx >/dev/null 2>&1 || fail "user removed without --purge"
sh $U >/dev/null 2>&1 && ok "second uninstall idempotent" || fail "second uninstall failed"

# 3. reinstall reuses data, then purge + remove user
sh $I --from $F >/tmp/i2.log 2>&1; grep -q "keystore already exists" /tmp/i2.log && grep -q "keeping existing config" /tmp/i2.log || fail "reinstall did not keep data"
systemctl is-active -q redxd && healthy && ok "reinstall active" || fail "reinstall not active"
sh $U --purge --remove-user >/tmp/u2.log 2>&1 || fail "purge: $(cat /tmp/u2.log)"
for f in /var/lib/redx /etc/redx $UNIT /usr/local/bin/redxd; do [ -e $f ] && fail "purge left $f"; done
id redx >/dev/null 2>&1 && fail "user redx left"; getent group redx >/dev/null && fail "group redx left"
ok "purge removed data, config, unit, user"
sh $U --purge --remove-user >/dev/null 2>&1 && ok "second purge idempotent" || fail "second purge failed"

# 4. custom --prefix renders the unit with that bin dir; uninstall --prefix
sh $I --from $F --prefix /opt/redx >/dev/null 2>&1
grep -q '^ExecStart=/opt/redx/bin/redxd ' $UNIT && systemctl is-active -q redxd && healthy && ok "--prefix /opt/redx active" || fail "--prefix: $(grep ExecStart $UNIT)"
sh $U --prefix /opt/redx --purge --remove-user >/dev/null 2>&1; [ -e /opt/redx/bin/redxd ] && fail "--prefix binary left"
sh $I --from $F --prefix '/opt/re dx' >/dev/null 2>&1 && fail "unsafe --prefix accepted for the unit"
sh $U --prefix '/opt/re dx' --purge --remove-user >/dev/null 2>&1; rm -rf '/opt/re dx'

# 5. follower: enabled but not started; uninstall still clean
sh $I --from $F --role follower --peers https://10.0.0.1:7777 >/dev/null 2>&1
[ "$(systemctl is-enabled redxd)" = enabled ] && ! systemctl is-active -q redxd && ok "follower enabled, not started" || fail "follower state"
sh $U --purge --remove-user >/dev/null 2>&1; [ -e $UNIT ] && fail "follower unit left"

# 6. partial install: just a stray unit file and one binary, no user
install -m 0644 /src/deploy/systemd/redxd.service $UNIT; install -m 0755 $F/redx /usr/local/bin/redx
sh $U --purge --remove-user >/tmp/u3.log 2>&1 && [ ! -e $UNIT ] && [ ! -e /usr/local/bin/redx ] && ok "partial install removed" || fail "partial: $(cat /tmp/u3.log)"

# 7. .deb built from the same unit template: /usr/bin path, starts under systemd
cp $F/redxd $F/redx $F/redx-launcher /tmp/ 2>/dev/null; mkdir -p /tmp/debout
bash /src/deploy/linux/build-deb.sh 0.4.4 amd64 /bin-in /tmp/debout >/tmp/deb.log 2>&1 || fail "build-deb: $(cat /tmp/deb.log)"
DEB=$(ls /tmp/debout/*.deb 2>/dev/null | head -n1)
if [ -n "$DEB" ]; then
  dpkg-deb --fsys-tarfile "$DEB" | tar -xO ./lib/systemd/system/redxd.service > /tmp/deb.unit
  grep -q '^ExecStart=/usr/bin/redxd run --config /etc/redx/redx.toml --no-open$' /tmp/deb.unit && ! grep -q '@[A-Z]*@' /tmp/deb.unit && ok "deb unit rendered for /usr/bin" || fail "deb unit: $(grep ExecStart /tmp/deb.unit)"
  # the only difference between the two rendered units is the path
  grep -v '^#' /tmp/deb.unit | sed 's#/usr/bin#X#g; s#/usr/share/doc/redx#D#g' > /tmp/a; sh $I --from $F --no-service >/dev/null 2>&1
  grep -v '^#' /src/deploy/systemd/redxd.service | sed -e 's#@BINDIR@#X#g' -e 's#@DOCDIR@#D#g' > /tmp/b; cmp -s /tmp/a /tmp/b && ok "deb and install.sh units identical modulo paths" || fail "units differ: $(diff /tmp/a /tmp/b)"
  sh $U --purge --remove-user >/dev/null 2>&1
  dpkg -i "$DEB" >/tmp/dpkg.log 2>&1 || fail "dpkg -i: $(cat /tmp/dpkg.log)"
  systemctl enable --now redxd >/dev/null 2>&1; systemctl is-active -q redxd && healthy && ok "deb service active" || fail "deb service: $(journalctl -u redxd --no-pager -n 15)"
  dpkg -r redx >/dev/null 2>&1; systemctl is-active -q redxd && fail "deb remove left service running"
fi
[ "$FAILS" = 0 ] && echo PASS || { echo "$FAILS failure(s)"; exit 1; }
