#!/usr/bin/env python3
"""Migrate dnsmasq stand-in references to coredns_fwd in live code/profiles."""
from __future__ import annotations

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    for p in (ROOT / "profiles").glob("*.json"):
        t = p.read_text(encoding="utf-8")
        t2 = t.replace('"dnsmasq": "off"', '"coredns_fwd": "off"')
        t2 = t2.replace("vs dnsmasq off", "vs CoreDNS-forwarder off")
        t2 = t2.replace("Unbound strict vs dnsmasq off", "Unbound strict vs CoreDNS-forwarder off")
        if t2 != t:
            p.write_text(t2, encoding="utf-8")
            print("profile", p.name)

    for rel in (
        "classifier/run_adversarial.py",
        "classifier/run_robustness.py",
        "classifier/oracle_test.py",
        "docs/SCHEMA.md",
        "docs/ARCHITECTURE.md",
        "docs/ADVERSARIAL.md",
        "docs/THREAT-MODEL.md",
        "README.md",
    ):
        path = ROOT / rel
        if not path.is_file():
            continue
        t = path.read_text(encoding="utf-8")
        t2 = t.replace('"dnsmasq"', '"coredns_fwd"')
        t2 = t2.replace("'dnsmasq'", "'coredns_fwd'")
        # compose service restore lists
        t2 = t2.replace("\n            \"dnsmasq\",\n", "\n            \"coredns_fwd\",\n")
        t2 = t2.replace("| dnsmasq |", "| coredns_fwd |")
        t2 = t2.replace("Unbound + dnsmasq", "Unbound + CoreDNS-forwarder")
        t2 = t2.replace("`dnsmasq`", "`coredns_fwd`")
        t2 = t2.replace("| `dnsmasq` |", "| `coredns_fwd` |")
        t2 = t2.replace("dnsmasq stand-ins", "CoreDNS-forwarder stand-ins")
        t2 = t2.replace("Unbound and dnsmasq", "Unbound and CoreDNS-forwarder")
        if t2 != t:
            path.write_text(t2, encoding="utf-8")
            print("file", rel)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
