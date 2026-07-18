#!/usr/bin/env python3
"""UDP DNS MITM for StackDiff DNS-02 application-layer profiles.

Modes:
  passthrough          — forward upstream reply unchanged
  additional-glue      — append out-of-bailiwick A in ADDITIONAL
  malformed-truncated     — cut the upstream reply mid-packet
  malformed-bad-pointer — overwrite a name pointer to an invalid offset

Not a fuzzer. Deterministic transforms only.
"""

from __future__ import annotations

import argparse
import socket
import struct
import sys


def encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        if len(raw) > 63:
            raise ValueError(f"label too long: {label}")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def append_additional_a(packet: bytes, owner: str, ipv4: str, ttl: int = 60) -> bytes:
    """Append one ADDITIONAL A RR; bump ARCOUNT."""
    if len(packet) < 12:
        return packet
    id_, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", packet[:12])
    header = struct.pack("!HHHHHH", id_, flags, qd, an, ns, ar + 1)
    ip_bytes = bytes(int(x) for x in ipv4.split("."))
    if len(ip_bytes) != 4:
        raise ValueError(f"bad ipv4: {ipv4}")
    rr = encode_name(owner) + struct.pack("!HHIH", 1, 1, ttl, 4) + ip_bytes
    return header + packet[12:] + rr


def malformed_truncate(packet: bytes, keep: int = 20) -> bytes:
    if len(packet) <= keep:
        return packet
    return packet[:keep]


def malformed_bad_pointer(packet: bytes) -> bytes:
    """If a compression pointer exists in the answer region, poison it."""
    if len(packet) < 14:
        return malformed_truncate(packet, 14)
    data = bytearray(packet)
    # Scan for 0xC0 pointer bytes after the header; poison the offset byte.
    for i in range(12, min(len(data) - 1, 64)):
        if data[i] & 0xC0 == 0xC0:
            data[i + 1] = 0xFF  # almost certainly out of range
            return bytes(data)
    # No pointer found — fall back to truncate so the mode still bites.
    return malformed_truncate(packet, 18)


def transform(mode: str, packet: bytes) -> bytes:
    if mode == "passthrough":
        return packet
    if mode == "additional-glue":
        # Outside lab.stackdiff. bailiwick — classic glue-policy stress.
        return append_additional_a(packet, "ns.evil.test.", "198.51.100.66")
    if mode == "malformed-truncated":
        return malformed_truncate(packet)
    if mode == "malformed-bad-pointer":
        return malformed_bad_pointer(packet)
    raise SystemExit(f"unknown mode: {mode}")


def serve(listen: str, port: int, upstream: str, upstream_port: int, mode: str) -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((listen, port))
    print(f"mitm mode={mode} listen={listen}:{port} upstream={upstream}:{upstream_port}", flush=True)
    while True:
        data, addr = sock.recvfrom(4096)
        up = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        up.settimeout(2.0)
        try:
            up.sendto(data, (upstream, upstream_port))
            reply, _ = up.recvfrom(4096)
        except OSError as exc:
            print(f"upstream error from {addr}: {exc}", flush=True)
            up.close()
            continue
        up.close()
        try:
            out = transform(mode, reply)
        except Exception as exc:  # noqa: BLE001 — keep proxy alive
            print(f"transform error: {exc}", flush=True)
            out = reply
        sock.sendto(out, addr)


def main() -> int:
    p = argparse.ArgumentParser(description="StackDiff DNS MITM")
    p.add_argument("--listen", default="0.0.0.0")
    p.add_argument("--port", type=int, default=53)
    p.add_argument("--upstream", default="172.30.0.10")
    p.add_argument("--upstream-port", type=int, default=53)
    p.add_argument(
        "--mode",
        default="passthrough",
        choices=(
            "passthrough",
            "additional-glue",
            "malformed-truncated",
            "malformed-bad-pointer",
        ),
    )
    args = p.parse_args()
    try:
        serve(args.listen, args.port, args.upstream, args.upstream_port, args.mode)
    except KeyboardInterrupt:
        return 0
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
