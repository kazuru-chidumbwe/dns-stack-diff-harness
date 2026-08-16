#!/usr/bin/env python3
"""StackDiff Package C — robustness campaign (repeats + controls).

Gates strongly recommended:
  - repeated runs after clean-container restart
  - passthrough (agreeing) control
  - adversarial (divergent) profiles
  - optional role-order (dig order) probe

Does not claim prevalence. Records D(p)/axes stability for TNSM evidence depth.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import time
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
from oracle import (  # noqa: E402
    GLUE_AXES,
    SECURITY_AXES,
    SMOKE_AXES,
    compare_observations,
)
from run_adversarial import (  # noqa: E402
    INJECTOR_TO_MODE,
    bring_up,
    load_active_adversarial,
    run_one,
)
from run_smoke import RESOLVERS, collect_lab_environment, dig_query  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
COMPOSE_BASE = ROOT / "deploy" / "compose.yaml"
COMPOSE_ADV = ROOT / "deploy" / "compose.adversarial.yaml"


def restore_smoke_topology() -> None:
    subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE_BASE), "-f", str(COMPOSE_ADV), "stop", "mitm"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    subprocess.run(
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
            "auth",
        ],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
        timeout=180,
    )


def run_passthrough_control(query_name: str = "agree.lab.stackdiff.") -> dict:
    """Unmodified / agreeing control: MITM passthrough; expect smoke D=0."""
    bring_up("passthrough")
    time.sleep(5.0)
    observations: dict[str, dict] = {}
    for name, meta in RESOLVERS.items():
        observations[name] = dig_query(
            meta["host"], meta["port"], query_name, "A", timeout=4.0
        )
    smoke = compare_observations(observations, axes=SMOKE_AXES)
    security = compare_observations(observations, axes=SECURITY_AXES)
    return {
        "control": "passthrough-agree",
        "mitm_mode": "passthrough",
        "query": {"name": query_name, "type": "A"},
        "observations": observations,
        "oracle_smoke": smoke,
        "oracle_security": security,
        "expect": {"smoke_divergence_count": 0},
        "smoke_pass": smoke.get("divergence_count", 1) == 0,
    }


def run_one_role_order(profile: dict, reverse: bool) -> dict:
    """Same as run_one but dig order reversed when reverse=True."""
    mode = INJECTOR_TO_MODE[profile["injector"]]
    bring_up(mode)
    qname = profile["query"]["name"]
    time.sleep(5.0)
    order = list(RESOLVERS.items())
    if reverse:
        order = list(reversed(order))
    observations: dict[str, dict] = {}
    for name, meta in order:
        observations[name] = dig_query(
            meta["host"],
            meta["port"],
            qname,
            profile["query"]["type"],
            timeout=4.0,
        )
        observations[name].setdefault("additional", [])
        observations[name].setdefault("glue_cache_accept", None)
    axes = GLUE_AXES if mode == "additional-glue" else SECURITY_AXES
    if mode == "additional-glue":
        from run_adversarial import _attach_glue_probe

        _attach_glue_probe(observations)
    oracle = compare_observations(observations, axes=axes)
    return {
        "profile_id": profile["id"],
        "mitm_mode": mode,
        "dig_order": [n for n, _ in order],
        "observations": observations,
        "oracle": oracle,
    }


def summarize_repeats(rows: list[dict]) -> dict:
    counts = Counter(r["oracle"].get("divergence_count") for r in rows)
    axis_sets = Counter(
        tuple(sorted({d["axis"] for d in (r["oracle"].get("divergences") or [])}))
        for r in rows
    )
    modal_d, modal_d_n = counts.most_common(1)[0] if counts else (None, 0)
    modal_axes, modal_axes_n = axis_sets.most_common(1)[0] if axis_sets else ((), 0)
    return {
        "n": len(rows),
        "D_histogram": {str(k): v for k, v in sorted(counts.items(), key=lambda x: (x[0] is None, x[0]))},
        "modal_D": modal_d,
        "modal_D_fraction": (modal_d_n / len(rows)) if rows else None,
        "modal_axes": list(modal_axes),
        "modal_axes_fraction": (modal_axes_n / len(rows)) if rows else None,
        "stable_D": len(counts) == 1,
        "stable_axes": len(axis_sets) == 1,
    }


def write_markdown(out_dir: Path, report: dict) -> None:
    lines = [
        f"# Package C robustness — {report['stamp']}",
        "",
        f"- Host env: `{report['lab_environment'].get('uname_r')}` · Docker `{report['lab_environment'].get('docker_version')}`",
        f"- Repeats per adversarial profile: **{report['repeats']}**",
        f"- Controls: passthrough-agree × {report['control_repeats']}",
        f"- Role-order probes: {report['role_order_n']} (glue + malformed, reverse dig)",
        "",
        "## Passthrough control (expect smoke D=0)",
        "",
        f"- smoke_pass rate: **{report['controls']['passthrough']['smoke_pass_rate']}** "
        f"({report['controls']['passthrough']['smoke_pass_n']}/{report['controls']['passthrough']['n']})",
        f"- smoke D histogram: `{report['controls']['passthrough']['smoke_D_histogram']}`",
        f"- security-axis D histogram (AA/RA may differ): `{report['controls']['passthrough']['security_D_histogram']}`",
        "",
        "## Adversarial repeats",
        "",
    ]
    for pid, s in report["adversarial"].items():
        lines += [
            f"### {pid}",
            f"- n={s['n']} · modal D(p)={s['modal_D']} "
            f"({s['modal_D_fraction']:.2f}) · stable_D={s['stable_D']}",
            f"- modal axes: `{s['modal_axes']}` · stable_axes={s['stable_axes']}",
            f"- D histogram: `{s['D_histogram']}`",
            "",
        ]
    if report.get("role_order"):
        lines += ["## Role-order (reverse dig)", ""]
        for row in report["role_order"]:
            o = row["oracle"]
            axes = sorted({d["axis"] for d in (o.get("divergences") or [])})
            lines.append(
                f"- {row['profile_id']} dig_order={row['dig_order']} "
                f"D={o.get('divergence_count')} axes={axes}"
            )
        lines.append("")
    lines += [
        "## Interpretation (measurement honesty)",
        "",
        "- Stability of modal D(p)/axes under clean restarts supports instrument repeatability for the two profiles.",
        "- Passthrough smoke D=0 supports the agreeing-control gate.",
        "- This is still a laboratory robustness campaign — not production prevalence.",
        "",
    ]
    (out_dir / "SUMMARY.md").write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="StackDiff Package C robustness")
    parser.add_argument("--repeats", type=int, default=10, help="Repeats per adversarial profile")
    parser.add_argument("--control-repeats", type=int, default=5, help="Passthrough control repeats")
    parser.add_argument(
        "--profile",
        action="append",
        dest="profiles",
        help="Limit adversarial profile ids (default: both glue + malformed)",
    )
    parser.add_argument("--skip-role-order", action="store_true")
    args = parser.parse_args()

    selected = load_active_adversarial(args.profiles)
    if not selected:
        print("No adversarial profiles selected", file=sys.stderr)
        return 1

    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    out_dir = ROOT / "artifacts" / f"robustness-{stamp}"
    out_dir.mkdir(parents=True, exist_ok=True)
    lab = collect_lab_environment()

    # --- controls ---
    control_rows = []
    print(f"=== passthrough control ×{args.control_repeats} ===")
    for i in range(args.control_repeats):
        print(f"  control {i+1}/{args.control_repeats}")
        control_rows.append(run_passthrough_control())
    smoke_d = Counter(r["oracle_smoke"].get("divergence_count") for r in control_rows)
    sec_d = Counter(r["oracle_security"].get("divergence_count") for r in control_rows)
    smoke_pass_n = sum(1 for r in control_rows if r.get("smoke_pass"))
    controls = {
        "passthrough": {
            "n": len(control_rows),
            "smoke_pass_n": smoke_pass_n,
            "smoke_pass_rate": smoke_pass_n / len(control_rows) if control_rows else None,
            "smoke_D_histogram": {str(k): v for k, v in sorted(smoke_d.items())},
            "security_D_histogram": {str(k): v for k, v in sorted(sec_d.items())},
            "runs": control_rows,
        }
    }

    # --- adversarial repeats ---
    adv_raw: dict[str, list] = {p["id"]: [] for p in selected}
    for profile in selected:
        pid = profile["id"]
        print(f"=== {pid} ×{args.repeats} ===")
        for i in range(args.repeats):
            print(f"  {pid} {i+1}/{args.repeats}")
            adv_raw[pid].append(run_one(profile))

    adversarial = {pid: summarize_repeats(rows) for pid, rows in adv_raw.items()}
    # attach raw slim rows for archive
    for pid, rows in adv_raw.items():
        adversarial[pid]["runs"] = [
            {
                "divergence_count": r["oracle"].get("divergence_count"),
                "axes": sorted({d["axis"] for d in (r["oracle"].get("divergences") or [])}),
                "mitm_mode": r.get("mitm_mode"),
            }
            for r in rows
        ]

    # --- role order ---
    role_order = []
    if not args.skip_role_order:
        print("=== role-order reverse dig ===")
        for profile in selected:
            role_order.append(run_one_role_order(profile, reverse=True))

    restore_smoke_topology()
    # quick smoke after restore
    smoke_after = subprocess.run(
        ["python3", "classifier/run_smoke.py", "--compose-file", "deploy/compose.yaml"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )

    report = {
        "schema": "stackdiff.robustness.v1",
        "stamp": stamp,
        "role": "package_c_robustness",
        "lab_environment": lab,
        "repeats": args.repeats,
        "control_repeats": args.control_repeats,
        "role_order_n": len(role_order),
        "controls": {
            "passthrough": {
                k: v
                for k, v in controls["passthrough"].items()
                if k != "runs"
            }
        },
        "adversarial": {pid: {k: v for k, v in s.items() if k != "runs"} for pid, s in adversarial.items()},
        "adversarial_runs": {pid: s["runs"] for pid, s in adversarial.items()},
        "role_order": [
            {
                "profile_id": r["profile_id"],
                "dig_order": r["dig_order"],
                "divergence_count": r["oracle"].get("divergence_count"),
                "axes": sorted({d["axis"] for d in (r["oracle"].get("divergences") or [])}),
            }
            for r in role_order
        ],
        "post_smoke_rc": smoke_after.returncode,
        "post_smoke_tail": (smoke_after.stdout or "")[-500:],
    }

    # Full dump (includes control observations — useful for audit)
    full = {
        **report,
        "controls_full": controls,
        "role_order_full": role_order,
    }
    (out_dir / "manifest.json").write_text(
        json.dumps(full, indent=2, sort_keys=False) + "\n", encoding="utf-8"
    )
    write_markdown(out_dir, {**report, "controls": controls, "adversarial": adversarial, "role_order": role_order})
    print(json.dumps({k: report[k] for k in ("stamp", "adversarial", "controls") if k in report}, indent=2))
    # print compact adversarial
    print("adversarial:", json.dumps(report["adversarial"], indent=2))
    print("controls passthrough:", json.dumps(report["controls"]["passthrough"], indent=2))
    print("role_order:", json.dumps(report["role_order"], indent=2))
    print("wrote", out_dir)
    return 0 if smoke_after.returncode == 0 else 2


if __name__ == "__main__":
    raise SystemExit(main())
