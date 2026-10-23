#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
OUT="${PAGES_OUT:-$ROOT/_site}"

rm -rf "$OUT"
mkdir -p "$OUT/assets/screenshots"

cp -R "$ROOT/site/." "$OUT/"
cp "$ROOT/screenshots/optimized/"*.png "$OUT/assets/screenshots/"
cp "$ROOT/internal/web/static/favicon.svg" "$OUT/favicon.svg"
cp "$ROOT/LICENSE" "$OUT/LICENSE.txt"
touch "$OUT/.nojekyll"

echo "Built static site at $OUT"
