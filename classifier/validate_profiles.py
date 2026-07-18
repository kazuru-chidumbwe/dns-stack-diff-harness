"""Validate profile JSON against StackDiff v0 schema rules."""

from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROFILES = ROOT / "profiles"

REQUIRED = (
    "id",
    "intent",
    "status",
    "layer",
    "adversary",
    "dnssec_posture",
    "query",
    "class_hint",
)
ADV_REQUIRED = ("position", "capability", "win_condition")
DNSSEC_REQUIRED = ("mode", "unbound", "dnsmasq", "notes")
POSITIONS = {"none", "on-path", "off-path", "malicious-but-trusted-upstream"}
LAYERS = {"application", "os"}
STATUSES = {"active", "scaffold", "deferred-os-layer"}
DNSSEC_MODES = {"matched", "deliberately_mismatched"}


def validate_profile(path: Path) -> list[str]:
    errors: list[str] = []
    data = json.loads(path.read_text(encoding="utf-8"))
    for key in REQUIRED:
        if key not in data:
            errors.append(f"{path.name}: missing {key}")
    adv = data.get("adversary") or {}
    for key in ADV_REQUIRED:
        if key not in adv:
            errors.append(f"{path.name}: missing adversary.{key}")
    dnssec = data.get("dnssec_posture") or {}
    for key in DNSSEC_REQUIRED:
        if key not in dnssec:
            errors.append(f"{path.name}: missing dnssec_posture.{key}")
    if dnssec.get("mode") not in DNSSEC_MODES:
        errors.append(f"{path.name}: invalid dnssec_posture.mode")
    if data.get("layer") not in LAYERS:
        errors.append(f"{path.name}: invalid layer")
    if data.get("status") not in STATUSES:
        errors.append(f"{path.name}: invalid status")
    if adv.get("position") not in POSITIONS:
        errors.append(f"{path.name}: invalid adversary.position")
    if data.get("layer") == "os" and data.get("status") == "active":
        errors.append(f"{path.name}: os-layer profile cannot be active under v0 isolation")
    return errors


def main() -> int:
    errors: list[str] = []
    paths = sorted(PROFILES.glob("*.json"))
    for path in paths:
        errors.extend(validate_profile(path))
    if errors:
        print("SCHEMA FAIL", file=sys.stderr)
        for e in errors:
            print(e, file=sys.stderr)
        return 1
    print(f"SCHEMA OK ({len(paths)} profiles)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
