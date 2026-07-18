#!/usr/bin/env python3
"""StackDiff DNS-02 adversarial runner (application-layer MITM profiles).

Runs active profiles that declare an injector, through compose.adversarial.yaml.
Does NOT replace make smoke — smoke stays direct-to-auth oracle validation.

Findings language: manifests record divergences + class_hint only.
No “exploitable” claims without separate disclosure triage.
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

sys.path.insert(0, str(Path(__file__).resolve().parent))
from oracle import SECURITY_AXES, compare_observations  # noqa: E402
from run_smoke import (  # noqa: E402
    RESOLVERS,
    collect_lab_environment,
    dig_query,
)

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_BASE = ROOT / "deploy" / "compose.yaml"
COMPOSE_ADV = ROOT / "deploy" / "compose.adversarial.yaml"

INJECTOR_TO_MODE = {
    "mitm-additional-glue": "additional-glue",
    "mitm-malformed-response": "malformed-truncated",
}


def compose_cmd(*args: str, env: dict | None = None) -> subprocess.CompletedProcess:
    base_env = os.environ.copy()
    if env:
        base_env.update(env)
    cmd = [
        "docker",
        "compose",
        "-f",
        str(COMPOSE_BASE),
        "-f",
        str(COMPOSE_ADV),
        *args,
    ]
    return subprocess.run(
        cmd,
        cwd=str(ROOT),
        env=base_env,
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )


def bring_up(mode: str) -> None:
    # Ensure auth exists before MITM path is wired.
    auth = compose_cmd("up", "-d", "auth", env={"MITM_MODE": mode})
    if auth.returncode != 0:
        raise SystemExit(f"compose up auth failed:\n{auth.stdout}\n{auth.stderr}")
    proc = compose_cmd(
        "up",
        "-d",
        "--force-recreate",
        "mitm",
        "unbound",
        "dnsmasq",
        env={"MITM_MODE": mode},
    )
    if proc.returncode != 0:
        raise SystemExit(
            f"compose up failed (mode={mode}):\n{proc.stdout}\n{proc.stderr}"
        )


def wait_resolvers(query_name: str, deadline_s: float = 90.0) -> None:
    """Wait until both resolvers answer something (any RCODE or hard error counts as up)."""
    start = time.time()
    last = ""
    while time.time() - start < deadline_s:
        ready = True
        for meta in RESOLVERS.values():
            obs = dig_query(meta["host"], meta["port"], query_name, "A", timeout=3.0)
            # Ready if we got a DNS-shaped reply OR a transform-induced hard error.
            if obs.get("rcode") is None and not obs.get("error"):
                ready = False
                last = str(obs)
                break
            if obs.get("error") and "exit" in str(obs.get("error")):
                # dig exit without parse — may still be mid-restart
                if obs.get("rcode") is None and not obs.get("answers"):
                    # For malformed modes, dig exit is an acceptable "ready" signal
                    # once both sides have been queried at least once after recreate.
                    pass
        if ready:
            # Extra settle for Unbound forward after recreate.
            time.sleep(1.0)
            return
        time.sleep(2.0)
    raise SystemExit(f"resolvers not ready within timeout; last={last}")


def load_active_adversarial(profile_ids: list[str] | None) -> list[dict]:
    profiles: list[dict] = []
    for path in sorted((ROOT / "profiles").glob("*.json")):
        data = json.loads(path.read_text(encoding="utf-8"))
        data["_path"] = str(path.relative_to(ROOT).as_posix())
        if data.get("status") != "active":
            continue
        if data.get("id") == "P-SMOKE-AGREE":
            continue
        if not data.get("injector"):
            continue
        if profile_ids and data.get("id") not in profile_ids:
            continue
        if data["injector"] not in INJECTOR_TO_MODE:
            raise SystemExit(f"unknown injector {data['injector']} in {path.name}")
        profiles.append(data)
    return profiles


def run_one(profile: dict) -> dict:
    mode = INJECTOR_TO_MODE[profile["injector"]]
    bring_up(mode)
    qname = profile["query"]["name"]
    # For malformed modes dig may fail; still wait for at least UDP reachability
    # via agree.lab.stackdiff under passthrough settle — then switch is already done.
    # After recreate with adversarial mode, probe the profile query directly.
    time.sleep(5.0)

    observations: dict[str, dict] = {}
    for name, meta in RESOLVERS.items():
        observations[name] = dig_query(
            meta["host"],
            meta["port"],
            qname,
            profile["query"]["type"],
            timeout=4.0,
        )

    oracle = compare_observations(observations, axes=SECURITY_AXES)
    # Measurement axes for DNS-02 table (broader than smoke).
    return {
        "profile_id": profile["id"],
        "injector": profile["injector"],
        "mitm_mode": mode,
        "adversary": profile.get("adversary"),
        "dnssec_posture": profile.get("dnssec_posture"),
        "query": profile.get("query"),
        "observations": observations,
        "oracle": oracle,
        "class_hint": profile.get("class_hint"),
        "triage_note": (
            "Divergence recorded only. Class A/B assignment requires root-cause "
            "notes; do not publish as exploitable without disclosure process."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser(description="StackDiff DNS-02 adversarial runner")
    parser.add_argument(
        "--profile",
        action="append",
        dest="profiles",
        help="Profile id to run (repeatable). Default: all active adversarial.",
    )
    args = parser.parse_args()

    selected = load_active_adversarial(args.profiles)
    if not selected:
        print("No active adversarial profiles to run.", file=sys.stderr)
        return 1

    lab = collect_lab_environment()
    ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = ROOT / "artifacts" / f"adversarial-{ts}"
    out_dir.mkdir(parents=True, exist_ok=True)

    results = []
    for profile in selected:
        print(f"=== {profile['id']} injector={profile['injector']} ===")
        results.append(run_one(profile))

    # Restore smoke topology (direct to auth — no MITM overlay mounts).
    restore = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(COMPOSE_BASE),
            "-f",
            str(COMPOSE_ADV),
            "stop",
            "mitm",
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    _ = restore
    base = subprocess.run(
        [
            "docker",
            "compose",
            "-f",
            str(COMPOSE_BASE),
            "up",
            "-d",
            "--force-recreate",
            "--remove-orphans",
            "unbound",
            "dnsmasq",
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )
    if base.returncode != 0:
        print(
            f"warning: failed to restore smoke topology:\n{base.stdout}\n{base.stderr}",
            file=sys.stderr,
        )

    table = []
    for r in results:
        div = r["oracle"].get("divergences") or []
        table.append(
            {
                "profile_id": r["profile_id"],
                "mitm_mode": r["mitm_mode"],
                "divergence_count": r["oracle"].get("divergence_count"),
                "axes": sorted({d["axis"] for d in div}),
                "class_hint": r.get("class_hint"),
                "oracle_class_hint": r["oracle"].get("class_hint"),
            }
        )

    manifest = {
        "schema": "stackdiff.adversarial.v0",
        "created_utc": datetime.now(timezone.utc).isoformat(),
        "role": "dns02_application_layer_mitm",
        "lab_environment": lab,
        "results": results,
        "summary_table": table,
        "disclaimer": (
            "Measurement only. No CVE / exploitable claims in this manifest. "
            "Smoke oracle remains make smoke on compose.yaml without this overlay."
        ),
    }
    path = out_dir / "manifest.json"
    path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {path}")
    print(json.dumps(table, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
