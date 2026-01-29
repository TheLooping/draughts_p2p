#!/usr/bin/env bash
set -euo pipefail

CONFIGS_DIR=${1:-config/generated}
BINARY=${2:-./build/draughts_node}
RUN_DIR=${3:-run}

if [[ ! -x "$BINARY" ]]; then
  echo "binary not found or not executable: $BINARY" >&2
  exit 1
fi

mkdir -p "$RUN_DIR"
PID_FILE="$RUN_DIR/nodes.pids"
: > "$PID_FILE"

shopt -s nullglob
configs=("$CONFIGS_DIR"/*.conf)
if [[ ${#configs[@]} -eq 0 ]]; then
  echo "no configs found in $CONFIGS_DIR" >&2
  exit 1
fi

for cfg in "${configs[@]}"; do
  name=$(basename "$cfg" .conf)
  out="$RUN_DIR/$name.out"
  "$BINARY" "$cfg" > "$out" 2>&1 &
  echo "$! $cfg" >> "$PID_FILE"
  echo "started $cfg (pid=$!)"
  sleep 0.05
done

echo "pids saved to $PID_FILE"
