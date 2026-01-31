#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd "$(dirname "$0")/.." && pwd)

"$ROOT/scripts/stop_nodes.sh" "$ROOT/run/nodes.pids" || true

rm -rf "$ROOT/run" \
       "$ROOT/logs" \
       "$ROOT/neighbors" \
       "$ROOT/peers" \
       "$ROOT/config/generated" \
       "$ROOT/topology_state.json" \
       "$ROOT/topology_matrix.csv"

echo "cleaned experiment artifacts"
