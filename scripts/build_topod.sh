#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)
CALLER_PWD=$(pwd -P)
OUT=${1:-"$ROOT/build/TopoDaemon"}
if [[ "$OUT" != /* ]]; then
  OUT="$CALLER_PWD/$OUT"
fi

mkdir -p "$(dirname "$OUT")"

cd "$ROOT/src/TopoDaemon"
go build -o "$OUT" .

chmod +x "$OUT"
echo "built TopoDaemon -> $OUT"
