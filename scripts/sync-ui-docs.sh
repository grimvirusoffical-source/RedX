#!/bin/sh
# Copies the documents the console shows under Help into the embedded UI folder.
# Run after editing docs/{console,boxql,box-grammar,hosting,clustering,connect,secrets}.md. A Go test fails if they drift.
set -eu
cd "$(dirname "$0")/.."
mkdir -p host/ui/docs
for f in console boxql box-grammar hosting clustering connect secrets; do
  cp "docs/$f.md" "host/ui/docs/$f.md"
done
echo "synced ui docs"
