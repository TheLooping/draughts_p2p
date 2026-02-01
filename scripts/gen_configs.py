#!/usr/bin/env python3
import argparse
import base64
import json
import os
from pathlib import Path
import random
import subprocess
import sys
from typing import List, Set, Tuple

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
self_info_file = {self_info_file}
peer_info_dir = {peer_info_dir}
identity_key_file = {identity_key_file}
static_topology = {static_topology}
topology_dir = {topology_dir}

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
    p = argparse.ArgumentParser(description="Generate draughts_p2p configs + static topology + keys.")
    p.add_argument("--count", type=int, default=36, help="number of nodes to generate")
    p.add_argument("--bind-ip", default="127.0.0.1", help="IPv4 bind address shared by all nodes")
    p.add_argument("--overlay-base", type=int, default=4000, help="base overlay port")
    p.add_argument("--draughts-base", type=int, default=5000, help="base draughts port")
    p.add_argument("--out-dir", default="config/generated", help="output config directory")
    p.add_argument("--log-dir", default="logs", help="log directory")
    p.add_argument("--neighbors-dir", default="neighbors", help="active neighbor file directory")
    p.add_argument("--peer-info-dir", default="peers", help="self info file directory")
    p.add_argument("--keys-dir", default="keys", help="directory for SM2 keys")
    p.add_argument("--topology-dir", default="topology", help="directory for topology files")
    p.add_argument("--cli-count", type=int, default=0, help="how many nodes enable CLI (ignored if --cli-nodes set)")
    p.add_argument("--cli-nodes", default="10,20", help="comma-separated node indices to enable CLI")
    p.add_argument("--bootstrap-count", type=int, default=1, help="how many seed nodes to include as bootstraps")
    p.add_argument("--active-min", type=int, default=3, help="minimum active neighbors / degree")
    p.add_argument("--active-max", type=int, default=5, help="maximum active neighbors / degree")
    p.add_argument("--passive-max", type=int, default=80, help="maximum passive neighbors")
    p.add_argument("--neighbor-set-k", type=int, default=8, help="neighbors advertised in neighbor_set")
    p.add_argument("--neighbor-set-every-ms", type=int, default=5000, help="neighbor_set interval in ms")
    p.add_argument("--dynamic-topology", dest="static_topology", action="store_false",
                   help="use HyParView dynamic topology (bootstraps enabled)")
    p.add_argument("--force-keys", action="store_true", help="overwrite existing key files")
    p.add_argument("--seed", type=int, default=None, help="random seed for topology generation")
    p.set_defaults(static_topology=True)
    return p.parse_args()


def require_openssl() -> None:
    try:
        subprocess.run(["openssl", "version"], check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    except Exception as e:
        raise SystemExit(f"openssl not available: {e}")


def extract_pubkey_raw_base64(priv_path: Path) -> str:
    out = subprocess.check_output([
        "openssl", "ec", "-in", str(priv_path), "-text", "-noout"
    ], text=True)
    pub_hex = ""
    in_pub = False
    for line in out.splitlines():
        if line.strip() == "pub:":
            in_pub = True
            continue
        if in_pub:
            if not line.startswith(" "):
                break
            pub_hex += line.strip().replace(":", "")
    if not pub_hex:
        raise RuntimeError("failed to parse public key from openssl output")
    if pub_hex.startswith("04"):
        pub_hex = pub_hex[2:]
    raw = bytes.fromhex(pub_hex)
    if len(raw) != 64:
        raise RuntimeError(f"unexpected pubkey size: {len(raw)} bytes")
    return base64.b64encode(raw).decode("ascii")


def ensure_keypair(peer_id: str, keys_dir: Path, force: bool) -> Tuple[Path, str, Path]:
    priv_path = keys_dir / f"{peer_id}.pem"
    pub_path = keys_dir / f"{peer_id}.pub"
    if not force and priv_path.exists() and pub_path.exists():
        pub_b64 = pub_path.read_text().strip()
        if pub_b64:
            return priv_path, pub_b64, pub_path
    require_openssl()
    keys_dir.mkdir(parents=True, exist_ok=True)
    subprocess.run([
        "openssl", "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:sm2",
        "-out", str(priv_path)
    ], check=True)
    pub_b64 = extract_pubkey_raw_base64(priv_path)
    pub_path.write_text(pub_b64 + "\n")
    return priv_path, pub_b64, pub_path


def generate_connected_topology(n: int, min_deg: int, max_deg: int, rng: random.Random) -> List[Set[int]]:
    if n <= 0:
        raise ValueError("count must be > 0")
    if n == 1:
        if min_deg > 0:
            raise ValueError("min degree > 0 impossible for n=1")
        return [set()]
    if min_deg > max_deg:
        raise ValueError("active_min > active_max")

    max_deg = min(max_deg, n - 1)
    base_deg = 1 if n == 2 else 2
    if max_deg < base_deg:
        raise ValueError("active_max too small for connected topology")

    for _ in range(200):
        adj = [set() for _ in range(n)]
        order = list(range(n))
        rng.shuffle(order)
        for i in range(n):
            u = order[i]
            v = order[(i + 1) % n]
            adj[u].add(v)
            adj[v].add(u)

        def add_edge(u: int, v: int) -> bool:
            if u == v or v in adj[u]:
                return False
            if len(adj[u]) >= max_deg or len(adj[v]) >= max_deg:
                return False
            adj[u].add(v)
            adj[v].add(u)
            return True

        stalled = False
        while True:
            low = [i for i in range(n) if len(adj[i]) < min_deg]
            if not low:
                break
            low.sort(key=lambda i: (len(adj[i]), rng.random()))
            u = low[0]
            candidates = [v for v in range(n)
                          if v != u and v not in adj[u] and len(adj[v]) < max_deg]
            if not candidates:
                stalled = True
                break
            candidates.sort(key=lambda v: (len(adj[v]), rng.random()))
            add_edge(u, candidates[0])

        if stalled:
            continue
        return adj

    raise RuntimeError("failed to generate connected topology with given degree bounds")


def write_adjacency_matrix(node_ids: List[str], adj: List[Set[int]], out_path: Path) -> None:
    lines = []
    header = ["node_id"] + node_ids
    lines.append(",".join(header))
    for i, node in enumerate(node_ids):
        row = [node]
        neighbors = adj[i]
        for j in range(len(node_ids)):
            row.append("1" if j in neighbors else "0")
        lines.append(",".join(row))
    out_path.write_text("\n".join(lines) + "\n")


def main() -> None:
    args = parse_args()
    if args.count <= 0:
        raise SystemExit("--count must be > 0")

    out_dir = Path(args.out_dir)
    log_dir = Path(args.log_dir)
    neighbors_dir = Path(args.neighbors_dir)
    peer_info_dir = Path(args.peer_info_dir)
    keys_dir = Path(args.keys_dir)
    topology_dir = Path(args.topology_dir)

    out_dir.mkdir(parents=True, exist_ok=True)
    log_dir.mkdir(parents=True, exist_ok=True)
    neighbors_dir.mkdir(parents=True, exist_ok=True)
    peer_info_dir.mkdir(parents=True, exist_ok=True)
    keys_dir.mkdir(parents=True, exist_ok=True)
    topology_dir.mkdir(parents=True, exist_ok=True)

    seed_count = min(args.bootstrap_count, args.count)
    seeds = [
        f"{args.bind_ip}:{args.overlay_base + i}:{args.draughts_base + i}"
        for i in range(seed_count)
    ]

    cli_nodes = set()
    if args.cli_nodes:
        for item in args.cli_nodes.split(","):
            item = item.strip()
            if not item:
                continue
            try:
                cli_nodes.add(int(item))
            except ValueError:
                continue

    node_ids = [f"node{i}" for i in range(1, args.count + 1)]
    rng = random.Random(args.seed)

    adjacency: List[Set[int]] = [set() for _ in range(args.count)]
    if args.static_topology:
        adjacency = generate_connected_topology(args.count, args.active_min, args.active_max, rng)
        adjacency_json = {node_ids[i]: [node_ids[j] for j in sorted(neigh)]
                          for i, neigh in enumerate(adjacency)}
        (topology_dir / "adjacency.json").write_text(json.dumps(adjacency_json, indent=2))
        write_adjacency_matrix(node_ids, adjacency, topology_dir / "adjacency_matrix.csv")
        for i, node in enumerate(node_ids):
            path = topology_dir / f"{node}.neighbors"
            neighbors = [node_ids[j] for j in sorted(adjacency[i])]
            path.write_text("\n".join(neighbors) + "\n")

    for i, peer_id in enumerate(node_ids, start=1):
        overlay_port = args.overlay_base + (i - 1)
        draughts_port = args.draughts_base + (i - 1)
        if cli_nodes:
            cli_enabled = "true" if i in cli_nodes else "false"
        else:
            cli_enabled = "true" if i <= args.cli_count else "false"
        log_file = log_dir / f"{peer_id}.log"
        neighbors_file = neighbors_dir / f"{peer_id}.json"
        self_info_file = peer_info_dir / f"{peer_id}.info"

        priv_path, pub_b64, _ = ensure_keypair(peer_id, keys_dir, args.force_keys)
        self_info_file.write_text(
            "\n".join([
                f"peer_id = {peer_id}",
                f"bind_ip = {args.bind_ip}",
                f"overlay_port = {overlay_port}",
                f"draughts_port = {draughts_port}",
                f"pubkey = {pub_b64}",
                "",
            ])
        )

        bootstraps = []
        if not args.static_topology and i > 1:
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
            self_info_file=self_info_file.as_posix(),
            peer_info_dir=peer_info_dir.as_posix(),
            identity_key_file=priv_path.as_posix(),
            static_topology="true" if args.static_topology else "false",
            topology_dir=topology_dir.as_posix(),
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
    print(f"keys dir: {keys_dir}")
    print(f"peer info dir: {peer_info_dir}")
    if args.static_topology:
        print(f"topology dir: {topology_dir}")
        print(f"adjacency matrix: {topology_dir / 'adjacency_matrix.csv'}")
    else:
        print("dynamic topology enabled (bootstraps)")


if __name__ == "__main__":
    main()
