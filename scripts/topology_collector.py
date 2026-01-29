#!/usr/bin/env python3
import argparse
import json
import socket
from typing import Dict, List, Set


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Collect neighbor reports and output adjacency matrix.")
    p.add_argument("--bind", default="0.0.0.0", help="bind address")
    p.add_argument("--port", type=int, default=9000, help="UDP port to listen on")
    p.add_argument("--out", default="topology_matrix.csv", help="output CSV path")
    p.add_argument("--state", default="topology_state.json", help="state JSON path")
    return p.parse_args()


def build_matrix(state: Dict[str, dict]) -> str:
    nodes: Set[str] = set(state.keys())
    for payload in state.values():
        for n in payload.get("active_neighbors", []):
            peer_id = n.get("peer_id")
            if peer_id:
                nodes.add(peer_id)
    ordered = sorted(nodes)

    lines: List[str] = []
    header = ["node_id"] + ordered
    lines.append(",".join(header))

    neighbor_map = {
        k: {n.get("peer_id") for n in v.get("active_neighbors", []) if n.get("peer_id")}
        for k, v in state.items()
    }

    for node in ordered:
        row = [node]
        neighbors = neighbor_map.get(node, set())
        for target in ordered:
            row.append("1" if target in neighbors else "0")
        lines.append(",".join(row))

    return "\n".join(lines) + "\n"


def main() -> None:
    args = parse_args()

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((args.bind, args.port))

    state: Dict[str, dict] = {}
    print(f"listening on {args.bind}:{args.port}")

    while True:
        data, addr = sock.recvfrom(256 * 1024)
        try:
            payload = json.loads(data.decode("utf-8"))
        except Exception:
            continue
        peer_id = payload.get("peer_id")
        if not peer_id:
            continue
        state[peer_id] = payload

        # Write state and matrix atomically.
        with open(args.state + ".tmp", "w", encoding="utf-8") as f:
            json.dump(state, f, ensure_ascii=True, indent=2)
        with open(args.out + ".tmp", "w", encoding="utf-8") as f:
            f.write(build_matrix(state))
        import os
        os.replace(args.state + ".tmp", args.state)
        os.replace(args.out + ".tmp", args.out)

        print(f"updated from {peer_id} ({addr[0]}:{addr[1]}) -> {args.out}")


if __name__ == "__main__":
    main()
