#!/bin/sh
# Build e2e-oidc-idp from e2e-oidc-idp.patch in a throwaway worktree (shared branch untouched).
set -e
SRC=${REDX_SRC:-${REDX_E2E_ROOT:-$(cd "$(dirname "$0")/../../.." && pwd)}}
OUT=${1:-$SRC/bin/e2e-oidc-idp}
HERE=$(cd "$(dirname "$0")" && pwd)
WT=$(mktemp -d /tmp/redx-idp-wt-XXXX); rmdir "$WT"
git -C "$SRC" worktree add -q --detach "$WT" HEAD
trap 'git -C "$SRC" worktree remove --force "$WT"' EXIT
git -C "$WT" apply "$HERE/e2e-oidc-idp.patch"
(cd "$WT" && CGO_ENABLED=0 go build -trimpath -o "$OUT" ./cmd/e2e-oidc-idp)
echo "built $OUT"
