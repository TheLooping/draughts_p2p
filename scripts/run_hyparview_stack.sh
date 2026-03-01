#!/usr/bin/env bash
set -euo pipefail

CONFIGS_DIR="config/generated"
TOPOD_CONFIG_DIR="config/topod"
CHATCORE_BINARY="./build/draughts_node"
TOPOD_BINARY="./build/TopoDaemon"
RUN_DIR="run"
SKIP_LIST=""
ONLY_LIST=""
INTERVAL=1
TOPOD_DELAY=2

spawn_detached() {
  local out="$1"
  shift
  if command -v setsid >/dev/null 2>&1; then
    setsid "$@" > "$out" 2>&1 < /dev/null &
  else
    "$@" > "$out" 2>&1 &
  fi
}

usage() {
  cat <<EOF2
Usage: $0 [--configs-dir DIR] [--topod-config-dir DIR] [--chatcore-binary PATH] [--topod-binary PATH] [--run-dir DIR] [--skip name1,name2] [--only name1,name2] [--interval SEC] [--topod-delay SEC]
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
    --topod-config-dir) TOPOD_CONFIG_DIR="$2"; shift 2 ;;
    --chatcore-binary) CHATCORE_BINARY="$2"; shift 2 ;;
    --topod-binary) TOPOD_BINARY="$2"; shift 2 ;;
    --run-dir) RUN_DIR="$2"; shift 2 ;;
    --skip) SKIP_LIST=$(append_list "$SKIP_LIST" "$2"); shift 2 ;;
    --only) ONLY_LIST=$(append_list "$ONLY_LIST" "$2"); shift 2 ;;
    --interval) INTERVAL="$2"; shift 2 ;;
    --topod-delay) TOPOD_DELAY="$2"; shift 2 ;;
    -h|--help) usage; exit 0 ;;
    *) echo "unknown arg: $1" >&2; usage; exit 1 ;;
  esac
done

if [[ ! -x "$CHATCORE_BINARY" ]]; then
  echo "chatcore binary not found or not executable: $CHATCORE_BINARY" >&2
  exit 1
fi
if [[ ! -x "$TOPOD_BINARY" ]]; then
  echo "topod binary not found or not executable: $TOPOD_BINARY" >&2
  exit 1
fi

mkdir -p "$RUN_DIR"
TOPOD_PID_FILE="$RUN_DIR/hyparview_topod.pids"
CHATCORE_PID_FILE="$RUN_DIR/hyparview_chatcore.pids"
LEGACY_PID_FILE="$RUN_DIR/nodes.pids"
rm -f "$RUN_DIR"/*.out "$TOPOD_PID_FILE" "$CHATCORE_PID_FILE" "$LEGACY_PID_FILE"
: > "$TOPOD_PID_FILE"
: > "$CHATCORE_PID_FILE"
: > "$LEGACY_PID_FILE"

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
  echo "no configs to start after filtering" >&2
  exit 1
fi

start_topod() {
  local cfg=$1
  local name
  name=$(basename "$cfg" .conf)
  local topod_cfg="$TOPOD_CONFIG_DIR/$name.json"
  if [[ ! -f "$topod_cfg" ]]; then
    echo "missing topod config for $name: $topod_cfg" >&2
    exit 1
  fi
  local out="$RUN_DIR/$name.topod.out"
  spawn_detached "$out" "$TOPOD_BINARY" "$topod_cfg"
  echo "$! $topod_cfg" >> "$TOPOD_PID_FILE"
  echo "started TopoDaemon $name (pid=$!)"
}

start_chatcore() {
  local cfg=$1
  local name
  name=$(basename "$cfg" .conf)
  local out="$RUN_DIR/$name.chatcore.out"
  spawn_detached "$out" "$CHATCORE_BINARY" "$cfg"
  echo "$! $cfg" >> "$CHATCORE_PID_FILE"
  echo "$! $cfg" >> "$LEGACY_PID_FILE"
  echo "started ChatCore $name (pid=$!)"
}

for cfg in "${filtered[@]}"; do
  start_topod "$cfg"
  [[ "$INTERVAL" != "0" ]] && sleep "$INTERVAL"
done

[[ "$TOPOD_DELAY" != "0" ]] && sleep "$TOPOD_DELAY"

for cfg in "${filtered[@]}"; do
  start_chatcore "$cfg"
  [[ "$INTERVAL" != "0" ]] && sleep "$INTERVAL"
done

echo "topod pids saved to $TOPOD_PID_FILE"
echo "chatcore pids saved to $CHATCORE_PID_FILE"
echo "legacy chatcore pids saved to $LEGACY_PID_FILE"
