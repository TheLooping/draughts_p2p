#!/usr/bin/env bash
set -euo pipefail

CONFIGS_DIR="config/generated"
BINARY="./build/draughts_node"
RUN_DIR="run"
SEED_COUNT=0
SEED_DELAY=1
SKIP_LIST=""
ONLY_LIST=""
INTERVAL=5

usage() {
  cat <<EOF2
Usage: $0 [--configs-dir DIR] [--binary PATH] [--run-dir DIR] [--seed-count N] [--seed-delay SEC] [--skip name1,name2] [--only name1,name2] [--interval SEC]
EOF2
}

append_list() {
  local list="$1"
  local add="$2"
  if [[ -z "$add" ]]; then
    echo "$list"
    return
  fi
  if [[ -z "$list" ]]; then
    echo "$add"
  else
    echo "$list,$add"
  fi
}

in_list() {
  local item="$1"
  local list="$2"
  if [[ -z "$list" ]]; then
    return 1
  fi
  case ",$list," in
    *",$item,"*) return 0 ;;
    *) return 1 ;;
  esac
}

while [[ $# -gt 0 ]]; do
  case "$1" in
    --configs-dir) CONFIGS_DIR="$2"; shift 2 ;;
    --binary) BINARY="$2"; shift 2 ;;
    --run-dir) RUN_DIR="$2"; shift 2 ;;
    --seed-count) SEED_COUNT="$2"; shift 2 ;;
    --seed-delay) SEED_DELAY="$2"; shift 2 ;;
    --skip) SKIP_LIST=$(append_list "$SKIP_LIST" "$2"); shift 2 ;;
    --only) ONLY_LIST=$(append_list "$ONLY_LIST" "$2"); shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ ! -x "$BINARY" ]]; then
  echo "binary not found or not executable: $BINARY" >&2
  exit 1
fi

mkdir -p "$RUN_DIR"
PID_FILE="$RUN_DIR/nodes.pids"
rm -f "$RUN_DIR"/*.out "$PID_FILE"
: > "$PID_FILE"

shopt -s nullglob
configs=("$CONFIGS_DIR"/*.conf)
if [[ ${#configs[@]} -eq 0 ]]; then
  echo "no configs found in $CONFIGS_DIR" >&2
  exit 1
fi

filtered=()
for cfg in "${configs[@]}"; do
  base=$(basename "$cfg")
  base_no_ext=$(basename "$cfg" .conf)
  if [[ -n "$ONLY_LIST" ]]; then
    if ! in_list "$base" "$ONLY_LIST" && ! in_list "$base_no_ext" "$ONLY_LIST"; then
      continue
    fi
  fi
  if in_list "$base" "$SKIP_LIST" || in_list "$base_no_ext" "$SKIP_LIST"; then
    continue
  fi
  filtered+=("$cfg")
done

if [[ ${#filtered[@]} -eq 0 ]]; then
  echo "no configs to start after skipping" >&2
  exit 1
fi

start_cfg() {
  local cfg=$1
  local name
  name=$(basename "$cfg" .conf)
  local out="$RUN_DIR/$name.out"
  "$BINARY" "$cfg" > "$out" 2>&1 &
  echo "$! $cfg" >> "$PID_FILE"
  echo "started $cfg (pid=$!)"
}

if [[ "$SEED_COUNT" -gt 0 ]]; then
  for ((i=0; i<SEED_COUNT && i<${#filtered[@]}; i++)); do
    start_cfg "${filtered[$i]}"
    [[ "$INTERVAL" != "0" ]] && sleep "$INTERVAL"
  done
  sleep "$SEED_DELAY"
  for ((i=SEED_COUNT; i<${#filtered[@]}; i++)); do
    start_cfg "${filtered[$i]}"
    [[ "$INTERVAL" != "0" ]] && sleep "$INTERVAL"
  done
else
  for cfg in "${filtered[@]}"; do
    start_cfg "$cfg"
    [[ "$INTERVAL" != "0" ]] && sleep "$INTERVAL"
  done
fi

echo "pids saved to $PID_FILE"
