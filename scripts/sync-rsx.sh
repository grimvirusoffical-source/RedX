#!/usr/bin/env bash
# Vendor the pure-Go Red-SecretsXAI package (sdk/go/rsx) at a pinned commit.
#   scripts/sync-rsx.sh <red-secretsxai checkout> <commit>
# Copies it to internal/rsx (with tests and the shared vectors as testdata) and the
# library files only to sdk/go/internal/rsx. internal/rsx/VENDOR.txt records the commit
# and per-file SHA-256; internal/rsx/vendor_test.go checks both copies against it.
set -euo pipefail
src=${1:?red-secretsxai checkout}; rev=${2:?commit}
root=$(cd "$(dirname "$0")/.." && pwd)
tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT
git -C "$src" archive "$rev" sdk/go/rsx vectors | tar -x -C "$tmp"
full=$(git -C "$src" rev-parse "$rev")
for d in "$root/internal/rsx" "$root/sdk/go/internal/rsx"; do
  find "$d" -maxdepth 1 -type f \( -name '*.go' -o -name VENDOR.txt \) ! -name vendor_test.go -delete 2>/dev/null || true
  mkdir -p "$d"
done
rm -rf "$root/internal/rsx/testdata"
for f in "$tmp"/sdk/go/rsx/*.go; do
  b=$(basename "$f")
  [ "$b" = xcheck_test.go ] && continue          # needs the C++ tool; run in red-secretsxai
  cp "$f" "$root/internal/rsx/$b"
  case "$b" in *_test.go) ;; *) cp "$f" "$root/sdk/go/internal/rsx/$b" ;; esac
done
mkdir -p "$root/internal/rsx/testdata"
cp -r "$tmp/vectors" "$root/internal/rsx/testdata/vectors"
sed -i 's|var vecDir = filepath.Join("..", "..", "..", "vectors")|var vecDir = filepath.Join("testdata", "vectors")|' "$root/internal/rsx/vectors_test.go"
{
  echo "Red-SecretsXAI pure-Go package, vendored from sdk/go/rsx"
  echo "commit $full"
  echo "branch go-port"
  echo "Do not edit these files here: change Red-SecretsXAI and re-run scripts/sync-rsx.sh."
  echo "files (sha256 of the vendored library files):"
  (cd "$root/sdk/go/internal/rsx" && sha256sum *.go)
} > "$root/internal/rsx/VENDOR.txt"
echo "vendored $full"
