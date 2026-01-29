#!/usr/bin/env python3
import argparse
import glob
import os
import socket
import time


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Send neighbor JSON files to a collector.")
    p.add_argument("--dir", default="neighbors", help="directory containing neighbor files")
    p.add_argument("--pattern", default="*.json", help="glob pattern for neighbor files")
    p.add_argument("--host", required=True, help="collector host")
    p.add_argument("--port", type=int, required=True, help="collector port")
    p.add_argument("--interval", type=float, default=0.0, help="repeat every N seconds (0 = once)")
    return p.parse_args()


def send_once(sock: socket.socket, addr, files):
    for path in files:
        try:
            with open(path, "rb") as f:
                data = f.read()
            if data:
                sock.sendto(data, addr)
        except Exception:
            continue


def main() -> None:
    args = parse_args()
    addr = (args.host, args.port)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    while True:
        files = sorted(glob.glob(os.path.join(args.dir, args.pattern)))
        send_once(sock, addr, files)
        if args.interval <= 0:
            break
        time.sleep(args.interval)


if __name__ == "__main__":
    main()
