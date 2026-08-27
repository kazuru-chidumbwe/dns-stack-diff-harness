#!/usr/bin/env python3
"""CVE-2025-11411 positive-control gate (iterator + parent referral path).

Pass when known-vulnerable Unbound (default 1.24.0) accepts promiscuous zone-cut
NS from a positive A reply (vendor pollute1 shape), detected as:
  check.lab.stackdiff. → 198.51.100.99  (attacker) instead of auth 203.0.113.99

See docs/POSITIVE-CONTROL-CVE11411.md and vendor/cve-2025-11411/.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "classifier"))
from run_smoke import dig_query  # noqa: E402

ATTACKER_CHECK_IP = "198.51.100.99"
AUTH_CHECK_IP = "203.0.113.99"
ATTACKER_NS_IP = "172.30.0.66"
DEFAULT_IMAGE = "l33tlamer/unbound-recursive:1.24.0"
COMPOSE_FILES = [
    "deploy/compose.yaml",
    "deploy/compose.adversarial.yaml",
    "deploy/compose.iterate-pc.yaml",
]


def compose(args: list[str], env: dict[str, str] | None = None) -> subprocess.CompletedProcess[str]:
    base = {**os.environ, **(env or {})}
    cmd = ["docker", "compose", *[a for f in COMPOSE_FILES for a in ("-f", f)], *args]
    return subprocess.run(
        cmd,
        cwd=ROOT,
        env=base,
        text=True,
        capture_output=True,
        check=False,
        timeout=300,
    )


def dig_unbound(name: str, qtype: str = "A") -> dict:
    return dig_query("127.0.0.1", 9053, name, qtype, timeout=5.0)


def main() -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--image", default=DEFAULT_IMAGE, help="Vulnerable Unbound image")
    p.add_argument("--query", default="www.lab.stackdiff.", help="Positive A query for inject")
    p.add_argument("--keep", action="store_true", help="Leave compose up on exit")
    args = p.parse_args()

    env = {"MITM_MODE": "authority-ns-glue", "UNBOUND_IMAGE": args.image}
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = ROOT / "artifacts" / f"positive-control-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)

    print(
        f"PC: image={args.image} topology=parent-stub→referral→MITM mitm=authority-ns-glue",
        flush=True,
    )

    up = compose(
        ["up", "-d", "--force-recreate", "auth", "parent", "attacker", "mitm", "unbound"],
        env=env,
    )
    if up.returncode != 0:
        print(up.stdout)
        print(up.stderr, file=sys.stderr)
        (out_dir / "compose-up.err").write_text(up.stderr or up.stdout or "", encoding="utf-8")
        return 1

    deadline = time.time() + 120
    last: dict = {}
    while time.time() < deadline:
        last = dig_unbound("agree.lab.stackdiff.")
        if last.get("rcode") == "NOERROR" and last.get("answers"):
            break
        time.sleep(2)
    else:
        print(f"Unbound not ready: {last}", file=sys.stderr)
        (out_dir / "result.json").write_text(
            json.dumps({"pass": False, "error": "not_ready", "last": last}, indent=2) + "\n",
            encoding="utf-8",
        )
        if not args.keep:
            compose(["down"], env=env)
        return 1

    # Prime delegation via parent referral, then re-query under inject.
    prime = dig_unbound(args.query)
    time.sleep(0.5)
    inject = dig_unbound(args.query)
    time.sleep(0.5)
    check = dig_unbound("check.lab.stackdiff.")
    ns_probe = dig_unbound("ns.attacker.example.")

    check_answers = check.get("answers") or []
    accept = ATTACKER_CHECK_IP in check_answers
    still_auth = AUTH_CHECK_IP in check_answers
    glue_ns = ATTACKER_NS_IP in (ns_probe.get("answers") or [])

    result = {
        "gate": "positive-control-cve-2025-11411",
        "image": args.image,
        "topology": "stub stackdiff. → parent; lab.stackdiff NS via referral to MITM",
        "mitm_mode": "authority-ns-glue",
        "vendor_vector": "pollute1-shaped zone-cut NS in AUTHORITY of positive A reply",
        "vendor_source": "vendor/cve-2025-11411/patch_CVE-2025-11411_option_tests.diff",
        "query": args.query,
        "prime": prime,
        "inject_observation": inject,
        "check_observation": check,
        "ns_attacker_probe": ns_probe,
        "glue_cache_accept": accept,
        "check_still_auth": still_auth,
        "ns_attacker_resolved": glue_ns,
        "pass": accept,
        "notes": (
            "PASS = check.lab.stackdiff answered by attacker (198.51.100.99). "
            "That is the vendor-equivalent accept signal on iterator path."
        ),
    }
    (out_dir / "result.json").write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"glue_cache_accept": accept, "pass": accept, "artifact": str(out_dir)}, indent=2))

    if not args.keep:
        compose(["down"], env=env)

    return 0 if accept else 2


if __name__ == "__main__":
    raise SystemExit(main())
