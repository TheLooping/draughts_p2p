#!/usr/bin/env bash
set -euo pipefail

PID_FILE=${1:-run/nodes.pids}

if [[ ! -f "$PID_FILE" ]]; then
  echo "no pid file: $PID_FILE"
  exit 0
fi

while read -r pid cfg; do
  [[ -z "$pid" ]] && continue
  if kill -0 "$pid" 2>/dev/null; then
    kill "$pid" 2>/dev/null || true
  fi
done < "$PID_FILE"

sleep 0.5

while read -r pid cfg; do
  [[ -z "$pid" ]] && continue
  if kill -0 "$pid" 2>/dev/null; then
    kill -9 "$pid" 2>/dev/null || true
  fi
done < "$PID_FILE"

rm -f "$PID_FILE"

echo "stopped nodes from $PID_FILE"
