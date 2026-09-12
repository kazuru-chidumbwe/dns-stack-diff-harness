#!/bin/bash
# Real change-window instance: MITM mode held FIXED (additional-glue / P-GLUE-AUTHORITY-NS),
# the stand-in Unbound version is the thing that changes. Mirrors scripts/layer3_change_window.py's
# freeze -> change -> re-pin -> decide structure, but the changed field is the image tag, not MITM mode.
# Pre-fix CVE-2025-11411 image -> post-fix image, on the same Host B CoreDNS-forwarder pair.
set -euo pipefail
cd /opt/atlas/repos/dns-stack-diff-harness
cp -n deploy/compose.yaml deploy/compose.yaml.pin120 || true

set_unbound_image () {
  local image="$1"
  python3 - <<PY
from pathlib import Path
image = "${image}"
p = Path("deploy/compose.yaml")
lines = p.read_text().splitlines(True)
out = []
in_unbound = False
for line in lines:
    stripped = line.rstrip("\n")
    if stripped == "  unbound:":
        in_unbound = True
        out.append(line)
        continue
    if in_unbound:
        if stripped.startswith("  ") and not stripped.startswith("    ") and stripped != "  unbound:":
            in_unbound = False
        elif stripped.lstrip().startswith("image:"):
            out.append(f"    image: {image}\n")
            continue
    out.append(line)
p.write_text("".join(out))
PY
}

run_pin () {
  local label="$1"
  local image="$2"
  set_unbound_image "$image"
  echo "=== ${label} image=${image} ===" >&2
  docker pull "${image}" >&2
  python3 -m classifier.run_adversarial --profile P-GLUE-AUTHORITY-NS >&2
  local latest
  latest=$(ls -1td artifacts/adversarial-* | head -1)
  echo "${latest}"
}

PRE_IMAGE="l33tlamer/unbound-recursive:1.24.0"
POST_IMAGE="l33tlamer/unbound-recursive:1.25.1"

PRE_DIR=$(run_pin pre "${PRE_IMAGE}")
POST_DIR=$(run_pin post "${POST_IMAGE}")

cp deploy/compose.yaml.pin120 deploy/compose.yaml
echo "restored compose.yaml to pin" >&2

stamp=$(date -u +%Y%m%dT%H%M%SZ)
OUT="artifacts/change-window-version-${stamp}"
mkdir -p "${OUT}"

python3 - "$PRE_DIR" "$POST_DIR" "$PRE_IMAGE" "$POST_IMAGE" "$OUT" <<'PY'
import json
import sys
from pathlib import Path

pre_dir, post_dir, pre_image, post_image, out_dir = sys.argv[1:6]

pre = json.load(open(Path(pre_dir) / "manifest.json"))["results"][0]
post = json.load(open(Path(post_dir) / "manifest.json"))["results"][0]

d_pre = pre["oracle"]["divergence_count"]
d_post = post["oracle"]["divergence_count"]
axes_pre = sorted(d["axis"] for d in pre["oracle"]["divergences"])
axes_post = sorted(d["axis"] for d in post["oracle"]["divergences"])
new_axes = sorted(set(axes_post) - set(axes_pre))

if d_post > d_pre:
    decision = "HOLD"
    rationale = (
        f"D(p) grew from {d_pre} to {d_post} after changing Unbound {pre_image} -> {post_image} "
        f"under fixed MITM mode additional-glue (authority-ns-glue); axes={axes_post}; "
        f"new axes vs pre={new_axes}. Hold until understood."
    )
elif new_axes:
    decision = "HOLD"
    rationale = (
        f"D(p) count unchanged ({d_pre}) but divergent axes changed: pre={axes_pre} post={axes_post}; "
        f"new axes={new_axes}. Axis-set change, not just count, still triggers hold."
    )
else:
    decision = "PROMOTE"
    rationale = (
        f"D(p) pre={d_pre} post={d_post}, axes unchanged ({axes_post}). "
        f"Version change {pre_image} -> {post_image} did not grow disagreement under fixed MITM mode."
    )

report = {
    "gate": "layer3-version-window",
    "held_fixed": "mitm_mode=additional-glue (authority-ns-glue); dnssec_posture; compose topology; dig flags",
    "changed_field": "unbound_image",
    "pre": {"image": pre_image, "divergence_count": d_pre, "divergent_axes": axes_pre, "source": pre_dir},
    "post": {"image": post_image, "divergence_count": d_post, "divergent_axes": axes_post, "source": post_dir},
    "new_axes_vs_pre": new_axes,
    "decision": decision,
    "rationale": rationale,
    "branch": "version-bump (pair-mode); MITM mode held fixed -- contrast with layer3_change_window.py (MITM toggled, version fixed)",
}
Path(out_dir, "decision.json").write_text(json.dumps(report, indent=2) + "\n")
print(json.dumps(report, indent=2))
PY

sha256sum "${OUT}/decision.json" | tee "${OUT}/decision.sha256"
echo "DONE ${OUT}"
