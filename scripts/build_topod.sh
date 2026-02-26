#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
OUT=${1:-"$ROOT/build/TopoDaemon"}

mkdir -p "$(dirname "$OUT")"

cd "$ROOT/src/TopoDaemon"
go build -o "$OUT" .

chmod +x "$OUT"
echo "built TopoDaemon -> $OUT"
