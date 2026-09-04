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
    # answer uses pointer to qname at offset 12
    answer = struct.pack("!HHHIH", 0xC00C, 1, 1, 60, 4) + bytes([203, 0, 113, 10])
    return header + question + answer


class MitmTests(unittest.TestCase):
    def test_glue_bumps_arcount(self) -> None:
        base = _minimal_answer()
        out = append_additional_a(base, "ns.evil.test.", "198.51.100.66")
        self.assertEqual(struct.unpack("!HHHHHH", out[:12])[5], 1)
        self.assertGreater(len(out), len(base))
        self.assertIn(encode_name("ns.evil.test."), out)

    def test_append_authority_helper_bumps_nscount_and_arcount(self) -> None:
        base = _minimal_answer()
        out = append_authority_ns_and_additional_a(
            base,
            zone="lab.stackdiff.",
            ns_name="ns.evil.test.",
            ipv4="198.51.100.66",
        )
        _id, _flags, qd, an, ns, ar = struct.unpack("!HHHHHH", out[:12])
        self.assertEqual(ns, 1)
        self.assertEqual(ar, 1)
        self.assertIn(encode_name("lab.stackdiff."), out)
        self.assertIn(encode_name("ns.evil.test."), out)
        self.assertIn(struct.pack("!HH", 2, 1), out)

    def test_pollute1_replace_authority_ar0(self) -> None:
        base = _minimal_answer()
        out = replace_authority_ns_pollute1(base)
        _id, _flags, qd, an, ns, ar = struct.unpack("!HHHHHH", out[:12])
        self.assertEqual(an, 1)
        self.assertEqual(ns, 1)
        self.assertEqual(ar, 0)
        self.assertIn(encode_name("lab.stackdiff."), out)
        self.assertIn(encode_name("ns.attacker.stackdiff."), out)
        self.assertNotIn(encode_name("ns.evil.test."), out)
        self.assertEqual(transform("authority-ns-glue", base), out)

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
