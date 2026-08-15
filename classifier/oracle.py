"""Divergence oracle helpers for StackDiff smoke / adversarial runs."""

from __future__ import annotations

from typing import Any, Iterable

SECURITY_AXES = (
    "rcode",
    "answers",
    "aa",
    "ra",
    "hang_or_crash",
)

# Glue / bailiwick measurement: client-visible ADDITIONAL + cache-accept probe.
# Used by DNS-02 P-GLUE-BAILIWICK; not part of smoke pass/fail.
GLUE_AXES = SECURITY_AXES + (
    "additional",
    "glue_cache_accept",
)

# Smoke axes only — exact harness-failure criterion for P-SMOKE-AGREE:
# both resolvers must agree on RCODE + answers, and neither may hard-error.
# Flag-only (AA/RA) differences are NOT a smoke failure.
SMOKE_AXES = (
    "rcode",
    "answers",
    "hang_or_crash",
)


def normalize_answers(answers: list[str] | None) -> list[str]:
    return sorted(a.strip().lower().rstrip(".") for a in (answers or []) if a)


def normalize_additional(records: list[str] | None) -> list[str]:
    """Normalize ADDITIONAL A rows as ``owner|ipv4`` (owner lower, no trailing dot)."""
    out: list[str] = []
    for raw in records or []:
        s = raw.strip().lower()
        if not s:
            continue
        if "|" in s:
            owner, ip = s.split("|", 1)
            out.append(f"{owner.rstrip('.')}|{ip.strip()}")
        else:
            out.append(s.rstrip("."))
    return sorted(out)


def compare_observations(
    obs: dict[str, dict[str, Any]],
    axes: Iterable[str] = SECURITY_AXES,
) -> dict[str, Any]:
    """Compare per-resolver observations on selected security-relevant axes.

    obs: {resolver_name: {rcode, answers, aa, ra, error, additional?, glue_cache_accept?}}
    """
    axis_set = tuple(axes)
    names = sorted(obs.keys())
    if len(names) < 2:
        return {
            "paired": False,
            "axes": list(axis_set),
            "divergences": [],
            "class_hint": "C",
            "detail": "need at least two resolvers",
        }

    divergences: list[dict[str, Any]] = []
    base = names[0]
    base_obs = obs[base]

    for other in names[1:]:
        o = obs[other]
        for axis in ("rcode", "aa", "ra", "glue_cache_accept"):
            if axis not in axis_set:
                continue
            if base_obs.get(axis) != o.get(axis):
                divergences.append(
                    {
                        "axis": axis,
                        "left": base,
                        "right": other,
                        "left_value": base_obs.get(axis),
                        "right_value": o.get(axis),
                    }
                )
        if "answers" in axis_set:
            if normalize_answers(base_obs.get("answers")) != normalize_answers(o.get("answers")):
                divergences.append(
                    {
                        "axis": "answers",
                        "left": base,
                        "right": other,
                        "left_value": normalize_answers(base_obs.get("answers")),
                        "right_value": normalize_answers(o.get("answers")),
                    }
                )
        if "additional" in axis_set:
            left_add = normalize_additional(base_obs.get("additional"))
            right_add = normalize_additional(o.get("additional"))
            if left_add != right_add:
                divergences.append(
                    {
                        "axis": "additional",
                        "left": base,
                        "right": other,
                        "left_value": left_add,
                        "right_value": right_add,
                    }
                )
        if "hang_or_crash" in axis_set:
            if bool(base_obs.get("error")) != bool(o.get("error")):
                divergences.append(
                    {
                        "axis": "hang_or_crash",
                        "left": base,
                        "right": other,
                        "left_value": base_obs.get("error"),
                        "right_value": o.get("error"),
                    }
                )

    class_hint = "pass" if not divergences else "C_until_triaged"
    return {
        "paired": True,
        "axes": list(axis_set),
        "resolvers": names,
        "divergences": divergences,
        "divergence_count": len(divergences),
        "class_hint": class_hint,
    }
