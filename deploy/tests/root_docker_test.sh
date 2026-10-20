#!/bin/sh
# Root-mode installer tests, ONLY inside a disposable docker container running real systemd (PID 1), so
# service enable/start/stop/disable is exercised for real. Never runs a root install on the host.
# Usage: root_docker_test.sh <bin dir with linux redxd, redx, redx-launcher>    (needs docker; uses sudo if needed)
set -eu
B=$(cd "$1" && pwd); R=$(cd "$(dirname "$0")/../.." && pwd)
D=docker; $D info >/dev/null 2>&1 || D="sudo -n docker"
IMG=redx-systemd-test:trixie; NAME="redx-root-test-$$"
trap '$D rm -f "$NAME" >/dev/null 2>&1 || true' EXIT INT TERM
printf 'FROM debian:trixie\nRUN apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq --no-install-recommends systemd systemd-sysv curl procps passwd adduser dpkg ca-certificates >/dev/null && rm -rf /var/lib/apt/lists/*\nCMD ["/sbin/init"]\n' \
  | $D build -q -t "$IMG" - >/dev/null
$D run -d --name "$NAME" --privileged --cgroupns=private --tmpfs /run --tmpfs /run/lock "$IMG" >/dev/null
for i in $(seq 60); do S=$($D exec "$NAME" systemctl is-system-running 2>/dev/null || true); case "$S" in running|degraded) break;; esac; sleep 0.5; done
$D exec "$NAME" mkdir -p /src/deploy /src/docs /src/assets /bin-in
$D cp "$R/deploy/." "$NAME:/src/deploy/"
$D cp "$R/assets/." "$NAME:/src/assets/"; $D cp "$R/LICENSE" "$NAME:/src/LICENSE"
for f in redxd redx redx-launcher; do $D cp "$B/$f" "$NAME:/bin-in/$f"; done
$D exec "$NAME" sh /src/deploy/tests/root_inner.sh
