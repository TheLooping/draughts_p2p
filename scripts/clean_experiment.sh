#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)

"$ROOT/scripts/stop_nodes.sh" "$ROOT/run/nodes.pids" || true

if pgrep -f "$ROOT/build/draughts_node" >/dev/null 2>&1; then
  pkill -TERM -f "$ROOT/build/draughts_node" || true
  sleep 0.5
  pkill -KILL -f "$ROOT/build/draughts_node" || true
fi

if pgrep -f "$ROOT/scripts/topology_collector.py" >/dev/null 2>&1; then
  pkill -TERM -f "$ROOT/scripts/topology_collector.py" || true
fi

if pgrep -f "$ROOT/scripts/send_neighbors.py" >/dev/null 2>&1; then
  pkill -TERM -f "$ROOT/scripts/send_neighbors.py" || true
fi

rm -rf "$ROOT/run" \
       "$ROOT/logs" \
       "$ROOT/neighbors" \
       "$ROOT/peers" \
       "$ROOT/config/generated" \
       "$ROOT/topology_state.json" \
       "$ROOT/topology_matrix.csv" \
       "$ROOT/draughts.log"

echo "cleaned experiment artifacts"
