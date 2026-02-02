#!/usr/bin/env python3
import argparse
import binascii
import json
import os
import subprocess
import sys
from typing import Dict, Any

INFO_STR = b"Draughts-EC-P256-ECDH-AES-CTR"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Replay initiator address transforms from trace logs.")
    p.add_argument("--trace-dir", required=True, help="trace directory containing trace.log and keys/")
    p.add_argument("--log", default="trace.log", help="trace log filename inside trace-dir")
    return p.parse_args()


def hkdf_sha256(ikm: bytes, length: int, info: bytes = b"") -> bytes:
    import hashlib
    import hmac

    salt = b""
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out = b""
    t = b""
    counter = 1
    while len(out) < length:
        t = hmac.new(prk, t + info + bytes([counter]), hashlib.sha256).digest()
        out += t
        counter += 1
    return out[:length]


def derive_secret(priv_pem: str, pub_pem: str) -> bytes:
    # Use openssl pkeyutl -derive to compute ECDH shared secret.
    try:
        res = subprocess.check_output([
            "openssl", "pkeyutl", "-derive",
            "-inkey", priv_pem,
            "-peerkey", pub_pem,
        ])
        return res
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"openssl pkeyutl -derive failed: {e}")


def aes_ctr_transform(key: bytes, iv: bytes, data: bytes) -> bytes:
    key_hex = binascii.hexlify(key).decode("ascii")
    iv_hex = binascii.hexlify(iv).decode("ascii")
    proc = subprocess.Popen([
        "openssl", "enc", "-aes-128-ctr",
        "-K", key_hex,
        "-iv", iv_hex,
        "-nosalt", "-nopad",
    ], stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
    out, err = proc.communicate(data)
    if proc.returncode != 0:
        raise RuntimeError(f"openssl enc failed: {err.decode('utf-8', 'ignore')}")
    return out


def normalize_path(base: str, rel: str) -> str:
    if os.path.isabs(rel):
        return rel
    return os.path.join(base, rel)


def main() -> int:
    args = parse_args()
    trace_dir = args.trace_dir
    log_path = os.path.join(trace_dir, args.log)
    if not os.path.isfile(log_path):
        print(f"trace log not found: {log_path}", file=sys.stderr)
        return 1

    with open(log_path, "r", encoding="utf-8") as f:
        lines = [line.strip() for line in f if line.strip()]

    for idx, line in enumerate(lines, start=1):
        try:
            entry: Dict[str, Any] = json.loads(line)
        except Exception as e:
            print(f"[{idx}] invalid json: {e}")
            continue

        before_hex = entry.get("before", "")
        after_hex = entry.get("after", "")
        priv_rel = entry.get("priv_key", "")
        pub_rel = entry.get("peer_pub", "")
        if not (before_hex and priv_rel and pub_rel):
            print(f"[{idx}] missing fields")
            continue

        priv_path = normalize_path(trace_dir, priv_rel)
        pub_path = normalize_path(trace_dir, pub_rel)
        if not os.path.isfile(priv_path) or not os.path.isfile(pub_path):
            print(f"[{idx}] missing key files: {priv_path} / {pub_path}")
            continue

        before = binascii.unhexlify(before_hex)
        secret = derive_secret(priv_path, pub_path)
        okm = hkdf_sha256(secret, 32, INFO_STR)
        key = okm[:16]
        iv = okm[16:]
        computed = aes_ctr_transform(key, iv, before)
        comp_hex = binascii.hexlify(computed).decode("ascii")

        stage = entry.get("stage", "")
        flow = entry.get("flow", "")
        field = entry.get("field", "")
        sid = entry.get("session", "")

        match = ""
        if after_hex:
            match = "OK" if after_hex.lower() == comp_hex.lower() else "MISMATCH"

        print(f"[{idx}] {flow}/{stage} {field} session={sid}")
        print(f"  before  : {before_hex}")
        print(f"  computed: {comp_hex} {match}")
        if after_hex:
            print(f"  after   : {after_hex}")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
