#!/usr/bin/env python3
"""Create and start one local draughts node that joins an existing network.

Features:
- Uses fixed bootstrap seeds from config/bootstrap_seeds.conf by default.
- Can override bootstrap list via --bootstrap.
- Auto-detects local bind IP.
- Auto-picks free ports from given ranges.
- Supports CLI and non-CLI startup mode.
"""

from __future__ import annotations

import argparse
import datetime as dt
import json
import os
from pathlib import Path
import re
import shlex
import socket
import subprocess
import sys
from typing import Iterable, List, Sequence, Tuple

from gen_configs import ensure_keypair


DEFAULT_BOOTSTRAP_FILE = "config/bootstrap_seeds.conf"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Generate/start one local join node")
    p.add_argument("--peer-id", default="", help="node id (auto-generated if empty)")
    p.add_argument("--cli", action="store_true", help="start ChatCore with CLI (foreground)")
    p.add_argument(
        "--bootstrap",
        default="",
        help="comma-separated bootstrap topod addresses, e.g. 192.168.150.115:6000,192.168.150.115:6001",
    )
    p.add_argument(
        "--bootstrap-file",
        default=DEFAULT_BOOTSTRAP_FILE,
        help=f"bootstrap file used when --bootstrap is empty (default: {DEFAULT_BOOTSTRAP_FILE})",
    )
    p.add_argument("--bind-ip", default="", help="bind IPv4 (auto-detect if empty)")
    p.add_argument("--overlay-range", default="7000-7499", help="overlay TCP port range")
    p.add_argument("--draughts-range", default="8000-8499", help="draughts UDP port range")
    p.add_argument("--topod-range", default="9000-9499", help="topod TCP port range")
    p.add_argument("--log-level", default="warn", choices=["detail", "debug", "info", "warn", "error"])

    p.add_argument("--config-dir", default="config/joined", help="chatcore config output dir")
    p.add_argument("--topod-config-dir", default="config/topod_joined", help="topod config output dir")
    p.add_argument("--peer-info-dir", default="peers/joined", help="peer info dir")
    p.add_argument("--keys-dir", default="keys/joined", help="keys dir")
    p.add_argument("--log-dir", default="logs/joined", help="log dir")
    p.add_argument("--neighbors-dir", default="neighbors/joined", help="neighbors dir")
    p.add_argument("--topology-dir", default="topology", help="topology dir")
    p.add_argument("--topod-socket-dir", default="run/topod", help="topod unix socket dir")
    p.add_argument("--run-dir", default="run", help="runtime output dir")

    p.add_argument("--active-min", type=int, default=3)
    p.add_argument("--active-max", type=int, default=5)
    p.add_argument("--topod-bootstrap", type=int, default=3, help="max bootstrap entries to keep")

    p.add_argument("--chatcore-binary", default="", help="override ChatCore binary path")
    p.add_argument("--topod-binary", default="./build/TopoDaemon", help="TopoDaemon binary path")
    p.add_argument("--dry-run", action="store_true", help="only generate config, do not start")
    p.add_argument("--force-key", action="store_true", help="overwrite existing private key for peer id")
    return p.parse_args()


def _clean_line(s: str) -> str:
    return s.split("#", 1)[0].strip()


def load_bootstrap_addrs(spec: str, bootstrap_file: str, limit: int) -> List[str]:
    addrs: List[str] = []
    if spec.strip():
        for item in spec.split(","):
            item = item.strip()
            if item:
                addrs.append(item)
    else:
        path = Path(bootstrap_file)
        if not path.exists():
            raise SystemExit(f"bootstrap file not found: {bootstrap_file}")
        for line in path.read_text().splitlines():
            line = _clean_line(line)
            if line:
                addrs.append(line)

    dedup: List[str] = []
    seen = set()
    for addr in addrs:
        if addr in seen:
            continue
        validate_addr(addr)
        seen.add(addr)
        dedup.append(addr)

    if not dedup:
        raise SystemExit("no bootstrap addresses provided")
    if limit > 0:
        dedup = dedup[:limit]
    return dedup


def validate_addr(addr: str) -> None:
    try:
        host, port_str = addr.rsplit(":", 1)
        host = host.strip()
        port = int(port_str)
    except Exception as e:  # pragma: no cover - defensive
        raise SystemExit(f"invalid bootstrap address: {addr}") from e
    if not host:
        raise SystemExit(f"invalid bootstrap address host: {addr}")
    if port <= 0 or port > 65535:
        raise SystemExit(f"invalid bootstrap address port: {addr}")


def parse_range(spec: str) -> Tuple[int, int]:
    m = re.fullmatch(r"\s*(\d+)\s*-\s*(\d+)\s*", spec)
    if not m:
        raise SystemExit(f"bad port range format: {spec}; expected START-END")
    start = int(m.group(1))
    end = int(m.group(2))
    if start <= 0 or end <= 0 or start > end or end > 65535:
        raise SystemExit(f"invalid port range: {spec}")
    return start, end


def can_bind_tcp(ip: str, port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        s.bind((ip, port))
    except OSError:
        s.close()
        return False
    s.close()
    return True


def can_bind_udp(ip: str, port: int) -> bool:
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.bind((ip, port))
    except OSError:
        s.close()
        return False
    s.close()
    return True


def pick_free_port(ip: str, spec: str, proto: str, used: set[int]) -> int:
    start, end = parse_range(spec)
    for port in range(start, end + 1):
        if port in used:
            continue
        ok = can_bind_tcp(ip, port) if proto == "tcp" else can_bind_udp(ip, port)
        if ok:
            used.add(port)
            return port
    raise SystemExit(f"no free {proto.upper()} port in range {spec} on {ip}")


def detect_bind_ip(bootstrap: Sequence[str]) -> str:
    # Prefer route towards first bootstrap.
    if bootstrap:
        host = bootstrap[0].rsplit(":", 1)[0].strip()
        port = int(bootstrap[0].rsplit(":", 1)[1])
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect((host, port))
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                return ip
        except OSError:
            pass
        finally:
            s.close()

    # Fallback to public route probe (no packet actually sent for UDP connect).
    for target in (("8.8.8.8", 53), ("1.1.1.1", 53)):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(target)
            ip = s.getsockname()[0]
            if ip and not ip.startswith("127."):
                return ip
        except OSError:
            pass
        finally:
            s.close()

    raise SystemExit("failed to auto-detect bind ip; pass --bind-ip explicitly")


def sanitize_peer_id(s: str) -> str:
    out = re.sub(r"[^A-Za-z0-9_.-]", "_", s.strip())
    return out.strip("._-")


def auto_peer_id(bind_ip: str, topod_port: int) -> str:
    host = sanitize_peer_id(socket.gethostname()) or "host"
    stamp = dt.datetime.now().strftime("%Y%m%d%H%M%S")
    last = bind_ip.split(".")[-1] if "." in bind_ip else "x"
    return f"node_{host}_{last}_{topod_port}_{stamp}"


def resolve_chatcore_binary(override: str) -> str:
    if override:
        return override
    candidates = ["./build/ChatCore", "./build/draughts_node"]
    for c in candidates:
        if os.path.isfile(c) and os.access(c, os.X_OK):
            return c
    raise SystemExit("chatcore binary not found; build first or pass --chatcore-binary")


def write_peer_info(path: Path, peer_id: str, bind_ip: str, overlay_port: int, draughts_port: int, pubkey_b64: str, topod_addr: str) -> None:
    path.write_text(
        "\n".join(
            [
                f"peer_id = {peer_id}",
                f"bind_ip = {bind_ip}",
                f"overlay_port = {overlay_port}",
                f"draughts_port = {draughts_port}",
                f"pubkey = {pubkey_b64}",
                f"topod_addr = {topod_addr}",
                "",
            ]
        )
    )


def write_chatcore_conf(path: Path, *, peer_id: str, bind_ip: str, overlay_port: int, draughts_port: int,
                       log_file: str, log_level: str, cli_enabled: bool, neighbors_file: str,
                       self_info_file: str, peer_info_dir: str, identity_key_file: str,
                       topology_dir: str, topod_ipc_socket: str, active_min: int, active_max: int) -> None:
    path.write_text(
        "\n".join(
            [
                f"peer_id = {peer_id}",
                f"bind_ip = {bind_ip}",
                f"overlay_port = {overlay_port}",
                f"draughts_port = {draughts_port}",
                f"log_file = {log_file}",
                f"log_level = {log_level}",
                f"cli_enabled = {'true' if cli_enabled else 'false'}",
                f"active_neighbors_file = {neighbors_file}",
                f"self_info_file = {self_info_file}",
                f"peer_info_dir = {peer_info_dir}",
                f"identity_key_file = {identity_key_file}",
                f"topology_dir = {topology_dir}",
                f"topod_ipc_socket = {topod_ipc_socket}",
                "topod_timeout_ms = 1500",
                "",
                f"active_min = {active_min}",
                f"active_max = {active_max}",
                "",
                "ciplc_a = 1.0",
                "ciplc_b = 0.1",
                "ciplc_c = 3.0",
                "ciplc_epsilon = 0.008",
                "ciplc_x0 = 0.03",
                "",
                "magic_num = 0x4452415547485453",
                "session_ttl_ms = 300000",
                "outnode_ttl_ms = 300000",
                "",
            ]
        )
    )


def write_topod_conf(path: Path, *, peer_id: str, listen_addr: str, ipc_socket: str, peer_info_dir: str,
                    bootstrap: Sequence[str], active_min: int, active_max: int) -> None:
    payload = {
        "peer_id": peer_id,
        "listen_addr": listen_addr,
        "ipc_socket": ipc_socket,
        "peer_info_dir": peer_info_dir,
        "snapshot_limit": 10,
        "shuffle_interval_ms": 30000,
        "keepalive_interval_ms": 8000,
        "join_retry_ms": 1200,
        "active_min": active_min,
        "active_max": active_max,
        "bootstrap": list(bootstrap),
    }
    path.write_text(json.dumps(payload, ensure_ascii=True, indent=2) + "\n")


def spawn_detached(cmd: Sequence[str], out_path: Path) -> int:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out = open(out_path, "ab", buffering=0)
    p = subprocess.Popen(cmd, stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, start_new_session=True)
    return p.pid


def append_pid(pid_file: Path, pid: int, cfg_path: Path) -> None:
    pid_file.parent.mkdir(parents=True, exist_ok=True)
    with pid_file.open("a", encoding="utf-8") as f:
        f.write(f"{pid} {cfg_path.as_posix()}\n")


def ensure_dirs(paths: Iterable[Path]) -> None:
    for p in paths:
        p.mkdir(parents=True, exist_ok=True)


def main() -> None:
    args = parse_args()

    bootstrap = load_bootstrap_addrs(args.bootstrap, args.bootstrap_file, args.topod_bootstrap)

    bind_ip = args.bind_ip.strip() or detect_bind_ip(bootstrap)

    used_ports: set[int] = set()
    overlay_port = pick_free_port(bind_ip, args.overlay_range, "tcp", used_ports)
    draughts_port = pick_free_port(bind_ip, args.draughts_range, "udp", used_ports)
    topod_port = pick_free_port(bind_ip, args.topod_range, "tcp", used_ports)

    peer_id = sanitize_peer_id(args.peer_id) if args.peer_id.strip() else auto_peer_id(bind_ip, topod_port)
    if not peer_id:
        raise SystemExit("peer_id is empty after sanitization")

    config_dir = Path(args.config_dir)
    topod_config_dir = Path(args.topod_config_dir)
    peer_info_dir = Path(args.peer_info_dir)
    keys_dir = Path(args.keys_dir)
    log_dir = Path(args.log_dir)
    neighbors_dir = Path(args.neighbors_dir)
    topod_socket_dir = Path(args.topod_socket_dir)
    run_dir = Path(args.run_dir)
    topology_dir = Path(args.topology_dir)

    ensure_dirs([
        config_dir,
        topod_config_dir,
        peer_info_dir,
        keys_dir,
        log_dir,
        neighbors_dir,
        topod_socket_dir,
        run_dir,
        topology_dir,
    ])

    chatcore_bin = resolve_chatcore_binary(args.chatcore_binary)
    topod_bin = args.topod_binary
    if not (os.path.isfile(topod_bin) and os.access(topod_bin, os.X_OK)):
        raise SystemExit(f"topod binary not found or not executable: {topod_bin}")

    priv_path, pub_b64, _ = ensure_keypair(peer_id, keys_dir, args.force_key)

    topod_addr = f"{bind_ip}:{topod_port}"
    self_info_path = peer_info_dir / f"{peer_id}.info"
    write_peer_info(self_info_path, peer_id, bind_ip, overlay_port, draughts_port, pub_b64, topod_addr)

    chat_cfg_path = config_dir / f"{peer_id}.conf"
    topod_cfg_path = topod_config_dir / f"{peer_id}.json"
    topod_sock = topod_socket_dir / f"{peer_id}.sock"

    write_chatcore_conf(
        chat_cfg_path,
        peer_id=peer_id,
        bind_ip=bind_ip,
        overlay_port=overlay_port,
        draughts_port=draughts_port,
        log_file=(log_dir / f"{peer_id}.log").as_posix(),
        log_level=args.log_level,
        cli_enabled=args.cli,
        neighbors_file=(neighbors_dir / f"{peer_id}.json").as_posix(),
        self_info_file=self_info_path.as_posix(),
        peer_info_dir=peer_info_dir.as_posix(),
        identity_key_file=priv_path.as_posix(),
        topology_dir=topology_dir.as_posix(),
        topod_ipc_socket=topod_sock.as_posix(),
        active_min=args.active_min,
        active_max=args.active_max,
    )

    write_topod_conf(
        topod_cfg_path,
        peer_id=peer_id,
        listen_addr=topod_addr,
        ipc_socket=topod_sock.as_posix(),
        peer_info_dir=peer_info_dir.as_posix(),
        bootstrap=bootstrap,
        active_min=args.active_min,
        active_max=args.active_max,
    )

    print(f"peer_id={peer_id}")
    print(f"bind_ip={bind_ip}")
    print(f"overlay_port={overlay_port}")
    print(f"draughts_port={draughts_port}")
    print(f"topod_port={topod_port}")
    print(f"bootstrap={bootstrap}")
    print(f"chatcore_config={chat_cfg_path.as_posix()}")
    print(f"topod_config={topod_cfg_path.as_posix()}")

    if args.dry_run:
        return

    topod_out = run_dir / f"{peer_id}.topod.out"
    chat_out = run_dir / f"{peer_id}.chatcore.out"
    topod_pid_file = run_dir / "joined_topod.pids"
    chat_pid_file = run_dir / "joined_chatcore.pids"

    topod_cmd = [topod_bin, topod_cfg_path.as_posix()]
    topod_pid = spawn_detached(topod_cmd, topod_out)
    append_pid(topod_pid_file, topod_pid, topod_cfg_path)
    print(f"started TopoDaemon pid={topod_pid}")

    if args.cli:
        print("starting ChatCore CLI in foreground...")
        print("command: " + shlex.join([chatcore_bin, chat_cfg_path.as_posix()]))
        subprocess.run([chatcore_bin, chat_cfg_path.as_posix()], check=False)
        return

    chat_pid = spawn_detached([chatcore_bin, chat_cfg_path.as_posix()], chat_out)
    append_pid(chat_pid_file, chat_pid, chat_cfg_path)
    print(f"started ChatCore pid={chat_pid}")


if __name__ == "__main__":
    main()
