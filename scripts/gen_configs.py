#!/usr/bin/env python3
import argparse
import os
from pathlib import Path

DEFAULT_TEMPLATE = """# Auto-generated config for draughts_p2p
peer_id = {peer_id}
bind_ip = {bind_ip}
overlay_port = {overlay_port}
draughts_port = {draughts_port}
{bootstraps_line}
log_file = {log_file}
log_level = {log_level}
cli_enabled = {cli_enabled}
active_neighbors_file = {neighbors_file}

# HyParView parameters
active_min = {active_min}
active_max = {active_max}
passive_max = {passive_max}

lease_ms = {lease_ms}
keepalive_every_ms = {keepalive_every_ms}
shuffle_every_ms = {shuffle_every_ms}
repair_every_ms = {repair_every_ms}

join_ttl = {join_ttl}
shuffle_k = {shuffle_k}

neighbor_set_every_ms = {neighbor_set_every_ms}
neighbor_set_k = {neighbor_set_k}

# CIPLC parameters
ciplc_a = {ciplc_a}
ciplc_b = {ciplc_b}
ciplc_c = {ciplc_c}
ciplc_epsilon = {ciplc_epsilon}
ciplc_x0 = {ciplc_x0}

# Draughts
magic_num = {magic_num}
session_ttl_ms = {session_ttl_ms}
outnode_ttl_ms = {outnode_ttl_ms}

# Padding (overlay messages only)
app_pad_to = {app_pad_to}
"""


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate draughts_p2p config files for multiple nodes.")
    p.add_argument("--count", type=int, default=10, help="number of nodes to generate")
    p.add_argument("--bind-ip", default="127.0.0.1", help="IPv4 bind address shared by all nodes")
    p.add_argument("--overlay-base", type=int, default=4000, help="base overlay port")
    p.add_argument("--draughts-base", type=int, default=5000, help="base draughts port")
    p.add_argument("--out-dir", default="config/generated", help="output config directory")
    p.add_argument("--log-dir", default="logs", help="log directory")
    p.add_argument("--neighbors-dir", default="neighbors", help="active neighbor file directory")
    p.add_argument("--cli-count", type=int, default=4, help="how many nodes enable CLI")
    p.add_argument("--bootstrap-count", type=int, default=3, help="how many seed nodes to include as bootstraps")
    p.add_argument("--active-min", type=int, default=4, help="minimum active neighbors")
    p.add_argument("--active-max", type=int, default=8, help="maximum active neighbors")
    p.add_argument("--passive-max", type=int, default=80, help="maximum passive neighbors")
    p.add_argument("--neighbor-set-k", type=int, default=8, help="neighbors advertised in neighbor_set")
    p.add_argument("--neighbor-set-every-ms", type=int, default=5000, help="neighbor_set interval in ms")
    return p.parse_args()


def main() -> None:
    args = parse_args()
    if args.count <= 0:
        raise SystemExit("--count must be > 0")

    out_dir = Path(args.out_dir)
    log_dir = Path(args.log_dir)
    neighbors_dir = Path(args.neighbors_dir)
    out_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    neighbors_dir.mkdir(parents=True, exist_ok=True)

    seed_count = min(args.bootstrap_count, args.count)
    seeds = [
        f"{args.bind_ip}:{args.overlay_base + i}:{args.draughts_base + i}"
        for i in range(seed_count)
    ]

    for i in range(1, args.count + 1):
        peer_id = f"node{i}"
        overlay_port = args.overlay_base + (i - 1)
        draughts_port = args.draughts_base + (i - 1)
        cli_enabled = "true" if i <= args.cli_count else "false"
        log_file = log_dir / f"{peer_id}.log"
        neighbors_file = neighbors_dir / f"{peer_id}.json"

        bootstraps = []
        if i > 1:
            for entry in seeds:
                if entry.endswith(f":{overlay_port}:{draughts_port}"):
                    continue
                bootstraps.append(entry)
        bootstraps_line = ""
        if bootstraps:
            bootstraps_line = "bootstraps = " + ",".join(bootstraps)

        content = DEFAULT_TEMPLATE.format(
            peer_id=peer_id,
            bind_ip=args.bind_ip,
            overlay_port=overlay_port,
            draughts_port=draughts_port,
            bootstraps_line=bootstraps_line,
            log_file=log_file.as_posix(),
            log_level="info",
            cli_enabled=cli_enabled,
            neighbors_file=neighbors_file.as_posix(),
            active_min=args.active_min,
            active_max=args.active_max,
            passive_max=args.passive_max,
            lease_ms=30000,
            keepalive_every_ms=10000,
            shuffle_every_ms=12000,
            repair_every_ms=2000,
            join_ttl=4,
            shuffle_k=8,
            neighbor_set_every_ms=args.neighbor_set_every_ms,
            neighbor_set_k=args.neighbor_set_k,
            ciplc_a=1.0,
            ciplc_b=0.1,
            ciplc_c=3.0,
            ciplc_epsilon=0.008,
            ciplc_x0=0.03,
            magic_num="0x4452415547485453",
            session_ttl_ms=300000,
            outnode_ttl_ms=300000,
            app_pad_to=0,
        )
        path = out_dir / f"{peer_id}.conf"
        path.write_text(content)

    print(f"generated {args.count} configs in {out_dir}")
    print(f"logs dir: {log_dir}")
    print(f"neighbors dir: {neighbors_dir}")


if __name__ == "__main__":
    main()
