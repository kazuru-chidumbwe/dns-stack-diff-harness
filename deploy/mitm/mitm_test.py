#!/usr/bin/env python3
"""Unit tests for MITM packet transforms (no Docker required)."""

from __future__ import annotations

import struct
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "deploy" / "mitm"))
from dns_mitm import (  # noqa: E402
    append_additional_a,
    append_authority_ns_and_additional_a,
    encode_name,
    malformed_bad_pointer,
    malformed_truncate,
    replace_authority_ns_pollute1,
    transform,
)


def _minimal_answer() -> bytes:
    # id=1, QR+AA+RD, qd=1 an=1 ns=0 ar=0, QNAME agree, A 203.0.113.10
    header = struct.pack("!HHHHHH", 1, 0x8400, 1, 1, 0, 0)
    qname = encode_name("agree.lab.stackdiff.")
    question = qname + struct.pack("!HH", 1, 1)
    answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + bytes([203, 0, 113, 10])
    return header + question + answer


class MitmTests(unittest.TestCase):
    def test_glue_bumps_arcount(self) -> None:
        base = _minimal_answer()
        out = append_additional_a(base, "ns.evil.test.", "198.51.100.66")
        self.assertEqual(struct.unpack("!HHHHHH", out[:12])[5], 1)
        self.assertGreater(len(out), len(base))
        self.assertIn(encode_name("ns.evil.test."), out)

    def test_pollute1_authority_only(self) -> None:
        base = _minimal_answer()
        out = replace_authority_ns_pollute1(
            base, zone="lab.stackdiff.", ns_name="ns.attacker.stackdiff."
        )
        _id, _flags, qd, an, ns, ar = struct.unpack("!HHHHHH", out[:12])
        self.assertEqual((an, ns, ar), (1, 1, 0))
        self.assertIn(encode_name("ns.attacker.stackdiff."), out)
        tout = transform("authority-ns-glue", base)
        self.assertEqual(struct.unpack("!HHHHHH", tout[:12])[4:], (1, 0))

    def test_legacy_append_name_is_replace(self) -> None:
        base = _minimal_answer()
        out = append_authority_ns_and_additional_a(
            base,
            zone="lab.stackdiff.",
            ns_name="ns.attacker.stackdiff.",
            ipv4="172.30.0.66",
        )
        self.assertEqual(struct.unpack("!HHHHHH", out[:12])[4:], (1, 0))

    def test_authority_ns_glue_replaces_existing_authority(self) -> None:
        header = struct.pack("!HHHHHH", 1, 0x8400, 1, 1, 1, 0)
        qname = encode_name("www.lab.stackdiff.")
        question = qname + struct.pack("!HH", 1, 1)
        answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + bytes([203, 0, 113, 20])
        legit_ns = (
            encode_name("lab.stackdiff.")
            + struct.pack("!HHIH", 2, 1, 60, len(encode_name("ns.lab.stackdiff.")))
            + encode_name("ns.lab.stackdiff.")
        )
        base = header + question + answer + legit_ns
        out = transform("authority-ns-glue", base)
        _id, _flags, qd, an, ns, ar = struct.unpack("!HHHHHH", out[:12])
        self.assertEqual(ns, 1)
        self.assertEqual(ar, 0)
        self.assertIn(encode_name("ns.attacker.stackdiff."), out)
        self.assertNotIn(encode_name("ns.lab.stackdiff."), out)

    def test_authority_ns_glue_skips_non_a(self) -> None:
        header = struct.pack("!HHHHHH", 1, 0x8400, 1, 1, 0, 0)
        qname = encode_name("lab.stackdiff.")
        question = qname + struct.pack("!HH", 2, 1)  # NS
        answer = struct.pack("!HHHIH", 0xC00C, 2, 1, 60, len(encode_name("ns.lab.stackdiff.")))
        answer += encode_name("ns.lab.stackdiff.")
        base = header + question + answer
        self.assertEqual(transform("authority-ns-glue", base), base)

    def test_truncate(self) -> None:
        base = _minimal_answer()
        out = malformed_truncate(base, 20)
        self.assertEqual(len(out), 20)

    def test_bad_pointer_poisons(self) -> None:
        base = _minimal_answer()
        out = malformed_bad_pointer(base)
        self.assertNotEqual(out, base)

    def test_transform_dispatch(self) -> None:
        base = _minimal_answer()
        self.assertEqual(transform("passthrough", base), base)
        self.assertGreater(len(transform("additional-glue", base)), len(base))


if __name__ == "__main__":
    raise SystemExit(unittest.main())
