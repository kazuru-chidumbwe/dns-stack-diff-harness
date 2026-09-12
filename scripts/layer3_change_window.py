#!/usr/bin/env python3
"""Layer-3 change-window instance (pair-mode) after L2 bounded-null branch."""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "classifier"))
from oracle import GLUE_AXES, compare_observations  # noqa: E402
from run_smoke import dig_query  # noqa: E402

COMPOSE_BASE = [
    "docker",
    "compose",
    "-f",
    str(ROOT / "deploy/compose.yaml"),
    "-f",
    str(ROOT / "deploy/compose.adversarial.yaml"),
]


def compose(args: list[str], mitm: str) -> None:
    env = {**os.environ, "MITM_MODE": mitm}
    r = subprocess.run(
        COMPOSE_BASE + args,
        cwd=ROOT,
        env=env,
        text=True,
        capture_output=True,
        check=False,
        timeout=240,
    )
    if r.returncode != 0:
        raise SystemExit(f"compose failed: {r.stderr or r.stdout}")


def wait_up(timeout: float = 90.0) -> None:
    end = time.time() + timeout
    last = {}
    while time.time() < end:
        last = {
            "unbound": dig_query("127.0.0.1", 9053, "agree.lab.stackdiff.", "A", timeout=3.0),
            "coredns_fwd": dig_query("127.0.0.1", 9054, "agree.lab.stackdiff.", "A", timeout=3.0),
        }
        if all(o.get("rcode") or o.get("error") for o in last.values()):
            return
        time.sleep(2)
    raise SystemExit(f"resolvers not ready: {last}")


def pin(label: str, mitm: str) -> dict:
    compose(["up", "-d", "--force-recreate", "auth", "mitm", "unbound", "coredns_fwd"], mitm)
    wait_up()
    obs = {
        "unbound": dig_query("127.0.0.1", 9053, "www.lab.stackdiff.", "A", timeout=4.0),
        "coredns_fwd": dig_query("127.0.0.1", 9054, "www.lab.stackdiff.", "A", timeout=4.0),
    }
    for o in obs.values():
        o.setdefault("additional", o.get("additional") or [])
        o.setdefault("glue_cache_accept", False)
    cmp = compare_observations(obs, GLUE_AXES)
    return {
        "label": label,
        "mitm_mode": mitm,
        "obs": obs,
        "divergence_count": cmp["divergence_count"],
        "divergent_axes": [d["axis"] for d in cmp["divergences"]],
        "all_null": cmp["all_null"],
    }


def main() -> int:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out = ROOT / "artifacts" / f"change-window-{stamp}"
    out.mkdir(parents=True, exist_ok=True)

    pre = pin("pre", "passthrough")
    post = pin("post-candidate", "additional-glue")
    d_pre, d_post = pre["divergence_count"], post["divergence_count"]
    if pre["all_null"] or post["all_null"]:
        decision = "INCONCLUSIVE"
        rationale = (
            f"pre_all_null={pre['all_null']} post_all_null={post['all_null']}: at least "
            "one pin got no DNS message from either stand-in, so D(p) is undefined (not "
            "evidence of agreement) — refusing to call this PROMOTE (Reviewer X item 4)."
        )
    elif d_post > d_pre:
        decision = "HOLD"
        rationale = (
            f"D(p) grew from {d_pre} to {d_post} after enabling additional-glue; "
            f"axes={post['divergent_axes']}. Hold until understood."
        )
    else:
        decision = "HOLD" if d_post else "PROMOTE"
        rationale = f"D(p) pre={d_pre} post={d_post} axes={post['divergent_axes']}."

    report = {
        "gate": "layer3-change-window",
        "stamp": stamp,
        "pre": pre,
        "post": post,
        "decision": decision,
        "rationale": rationale,
        "branch": "L2-bounded-null → axis-moving MITM mode change (pair-mode)",
    }
    raw = json.dumps(report, indent=2, sort_keys=True) + "\n"
    (out / "decision.json").write_text(raw, encoding="utf-8")
    sha = hashlib.sha256(raw.encode()).hexdigest()
    (out / "SHA256").write_text(sha + "\n", encoding="utf-8")
    (out / "DECISION.md").write_text(
        f"# Change-window instance {stamp}\n\n"
        f"**Decision:** {decision}\n\n{rationale}\n\n"
        f"- Pre: passthrough D={d_pre}\n- Post: additional-glue D={d_post}\n"
        f"- SHA-256: `{sha}`\n",
        encoding="utf-8",
    )
    print(json.dumps({"decision": decision, "D_pre": d_pre, "D_post": d_post, "artifact": str(out)}, indent=2))
    compose(["down"], "passthrough")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
