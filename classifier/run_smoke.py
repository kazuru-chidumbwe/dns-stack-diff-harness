#!/usr/bin/env python3
"""StackDiff smoke runner — oracle validation step (P-SMOKE-AGREE only).

Harness-failure criterion (exact):
  - Every resolver: RCODE == NOERROR
  - Every resolver: answers contain 203.0.113.10 (same RRset after normalize)
  - oracle(SMOKE_AXES).divergence_count == 0  (axes: rcode, answers, hang_or_crash)
  - AA/RA flag diffs are informational only — they do NOT fail smoke

Any failure here is Class C (harness bug). Do not treat as a security finding.
"""

from __future__ import annotations

import argparse
import json
import shutil
import socket
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from oracle import SMOKE_AXES, compare_observations  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
RESOLVERS = {
    "unbound": {"host": "127.0.0.1", "port": 9053},
    "dnsmasq": {"host": "127.0.0.1", "port": 9054},
}

RCODE_NAMES = {
    0: "NOERROR",
    1: "FORMERR",
    2: "SERVFAIL",
    3: "NXDOMAIN",
    4: "NOTIMP",
    5: "REFUSED",
}


def _encode_name(name: str) -> bytes:
    out = bytearray()
    for label in name.rstrip(".").split("."):
        raw = label.encode("ascii")
        out.append(len(raw))
        out.extend(raw)
    out.append(0)
    return bytes(out)


def _parse_name(buf: bytes, offset: int) -> tuple[str, int]:
    labels: list[str] = []
    jumped = False
    orig = offset
    for _ in range(64):
        if offset >= len(buf):
            raise ValueError("name truncated")
        length = buf[offset]
        if length == 0:
            offset += 1
            break
        if (length & 0xC0) == 0xC0:
            if offset + 1 >= len(buf):
                raise ValueError("pointer truncated")
            pointer = ((length & 0x3F) << 8) | buf[offset + 1]
            if not jumped:
                orig = offset + 2
            offset = pointer
            jumped = True
            continue
        offset += 1
        labels.append(buf[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(labels) + ".", (orig if jumped else offset)


def query_udp(host: str, port: int, name: str, qtype: str = "A", timeout: float = 2.0) -> dict:
    qtypes = {"A": 1, "AAAA": 28, "NS": 2, "CNAME": 5}
    qtype_id = qtypes.get(qtype.upper(), 1)
    txn = 0xA7A7
    header = struct.pack("!HHHHHH", txn, 0x0100, 1, 0, 0, 0)
    question = _encode_name(name) + struct.pack("!HH", qtype_id, 1)
    packet = header + question

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (host, port))
        data, _ = sock.recvfrom(4096)
    except OSError as exc:
        return {
            "rcode": None,
            "answers": [],
            "aa": None,
            "ra": None,
            "error": str(exc),
            "raw": "",
        }
    finally:
        sock.close()

    if len(data) < 12:
        return {
            "rcode": None,
            "answers": [],
            "aa": None,
            "ra": None,
            "error": "short response",
            "raw": data.hex(),
        }

    _id, flags, qdcount, ancount, _nscount, _arcount = struct.unpack("!HHHHHH", data[:12])
    rcode = RCODE_NAMES.get(flags & 0xF, str(flags & 0xF))
    aa = bool(flags & 0x0400)
    ra = bool(flags & 0x0080)
    offset = 12
    for _ in range(qdcount):
        _, offset = _parse_name(data, offset)
        offset += 4

    answers: list[str] = []
    for _ in range(ancount):
        _, offset = _parse_name(data, offset)
        if offset + 10 > len(data):
            break
        rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", data[offset : offset + 10])
        offset += 10
        rdata = data[offset : offset + rdlength]
        offset += rdlength
        if rtype == 1 and rdlength == 4:
            answers.append(".".join(str(b) for b in rdata))

    return {
        "rcode": rcode,
        "answers": answers,
        "aa": aa,
        "ra": ra,
        "error": None,
        "raw": f"udp flags=0x{flags:04x} ancount={ancount}",
    }


def dig_query(host: str, port: int, name: str, qtype: str, timeout: float = 3.0) -> dict:
    dig = shutil.which("dig")
    if not dig:
        return query_udp(host, port, name, qtype, timeout=timeout)

    cmd = [
        dig,
        f"@{host}",
        "-p",
        str(port),
        name,
        qtype,
        "+time=2",
        "+tries=1",
        "+noall",
        "+answer",
        "+comments",
    ]
    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired:
        return {
            "rcode": None,
            "answers": [],
            "aa": None,
            "ra": None,
            "error": "timeout",
            "raw": "",
        }

    raw = (proc.stdout or "") + (proc.stderr or "")
    rcode = None
    aa = None
    ra = None
    answers: list[str] = []
    for line in raw.splitlines():
        if "status:" in line:
            for part in line.split(","):
                part = part.strip()
                if part.startswith("status:"):
                    rcode = part.split(":", 1)[1].strip()
        if line.startswith(";; flags:"):
            flags = line.split(":", 1)[1].strip().split(";")[0]
            aa = "aa" in flags.split()
            ra = "ra" in flags.split()
        if line and not line.startswith(";") and qtype.upper() in line.split():
            cols = line.split()
            if len(cols) >= 5 and cols[3].upper() == qtype.upper():
                answers.append(cols[4])

    err = None
    if proc.returncode != 0 and not answers:
        err = f"dig exit {proc.returncode}"
    return {
        "rcode": rcode,
        "answers": answers,
        "aa": aa,
        "ra": ra,
        "error": err,
        "raw": raw.strip(),
    }


def wait_ready(deadline_s: float = 60.0) -> None:
    name = "agree.lab.stackdiff."
    start = time.time()
    last_err = ""
    while time.time() - start < deadline_s:
        ok = True
        for meta in RESOLVERS.values():
            obs = dig_query(meta["host"], meta["port"], name, "A")
            if obs.get("rcode") != "NOERROR" or "203.0.113.10" not in obs.get("answers", []):
                ok = False
                last_err = str(obs.get("error") or obs)
                break
        if ok:
            return
        time.sleep(2.0)
    raise SystemExit(f"resolvers not ready for P-SMOKE-AGREE within timeout; last={last_err}")


def collect_lab_environment() -> dict:
    """Record host facts for the pin — required for reproducible claims."""
    env: dict = {
        "uname_r": None,
        "uname_a": None,
        "docker_version": None,
        "platform": sys.platform,
    }
    try:
        env["uname_r"] = subprocess.check_output(
            ["uname", "-r"], text=True, timeout=5
        ).strip()
    except (OSError, subprocess.SubprocessError):
        # Windows Docker Desktop hosts often lack uname in PATH; try via docker.
        try:
            env["uname_r"] = subprocess.check_output(
                ["docker", "run", "--rm", "busybox", "uname", "-r"],
                text=True,
                timeout=60,
            ).strip()
            env["uname_r_source"] = "docker-busybox"
        except (OSError, subprocess.SubprocessError) as exc:
            env["uname_r_error"] = str(exc)
    try:
        env["uname_a"] = subprocess.check_output(
            ["uname", "-a"], text=True, timeout=5
        ).strip()
    except (OSError, subprocess.SubprocessError):
        pass
    try:
        env["docker_version"] = subprocess.check_output(
            ["docker", "version", "--format", "{{.Server.Version}}"],
            text=True,
            timeout=15,
        ).strip()
    except (OSError, subprocess.SubprocessError) as exc:
        env["docker_version_error"] = str(exc)
    return env


def main() -> int:
    parser = argparse.ArgumentParser(
        description="StackDiff oracle validation smoke (P-SMOKE-AGREE)"
    )
    parser.add_argument("--compose-file", default="deploy/compose.yaml")
    args = parser.parse_args()
    _ = args

    profile_path = ROOT / "profiles" / "p-smoke-agree.json"
    profile = json.loads(profile_path.read_text(encoding="utf-8"))

    wait_ready()

    observations: dict[str, dict] = {}
    for name, meta in RESOLVERS.items():
        observations[name] = dig_query(
            meta["host"],
            meta["port"],
            profile["query"]["name"],
            profile["query"]["type"],
        )

    oracle = compare_observations(observations, axes=SMOKE_AXES)
    # Record flag axes for triage without failing smoke on AA/RA alone.
    flag_oracle = compare_observations(observations, axes=("aa", "ra"))
    lab = collect_lab_environment()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = ROOT / "artifacts" / f"smoke-{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)

    # Exact pass predicate — keep in sync with module docstring.
    answers_ok = all(
        o.get("rcode") == "NOERROR" and "203.0.113.10" in o.get("answers", [])
        for o in observations.values()
    )
    passed = oracle.get("divergence_count", 1) == 0 and answers_ok

    manifest = {
        "schema": "stackdiff.smoke.v0",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "profile_id": profile["id"],
        "role": "oracle_validation_step",
        "harness_failure_criterion": {
            "axes": list(SMOKE_AXES),
            "required_rcode": "NOERROR",
            "required_answer_contains": "203.0.113.10",
            "flag_axes_informational": ["aa", "ra"],
            "on_fail": "Class C — stop; not a security finding",
        },
        "profile": profile,
        "resolvers": RESOLVERS,
        "observations": observations,
        "oracle": oracle,
        "flag_oracle_informational": flag_oracle,
        "smoke_pass_axes": list(SMOKE_AXES),
        "lab_environment": lab,
        "dns02_profiles": [
            "P-GLUE-BAILIWICK",
            "P-MALFORMED-RCODE",
        ],
        "deferred_os_profiles": [
            "P-OS-KLEIN-PRNG-DEFERRED",
            "P-OS-SAD-DNS-ICMP-DEFERRED",
        ],
        "pass": passed,
    }

    manifest_path = out_dir / "manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {manifest_path}")
    print(f"pass={manifest['pass']} divergences={oracle.get('divergence_count')}")
    print(f"lab.uname_r={lab.get('uname_r')} docker={lab.get('docker_version')}")

    if not manifest["pass"]:
        print(
            "SMOKE FAILED — harness/Class C. "
            "Required: identical NOERROR + RRset containing 203.0.113.10; no hang/crash. "
            "Do not treat as a security finding.",
            file=sys.stderr,
        )
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
