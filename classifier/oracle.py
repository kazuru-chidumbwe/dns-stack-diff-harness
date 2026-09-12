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

# Header / section axes that are undefined (⊥) when a role yields no DNS message.
NULL_GATED_AXES = frozenset(
    {
        "rcode",
        "answers",
        "aa",
        "ra",
        "additional",
        "glue_cache_accept",
    }
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


def has_dns_message(obs: dict[str, Any]) -> bool:
    """True if dig received a DNS response message (not client timeout / hard error)."""
    if obs.get("error"):
        return False
    # Explicit null rcode from parsers that record silence without error string.
    if obs.get("rcode") in (None, "", "null", "NULL"):
        return False
    return True


def classify_failure(error: str | None) -> str | None:
    """Normalize a raw dig-failure string into a comparable failure class.

    ``hang_or_crash`` used to compare only presence/absence of ``error``, which
    scored two different failure kinds (e.g. a client-side timeout vs. a hard
    connection/exit failure) as agreement just because both were truthy.
    Comparing classes instead catches that (Reviewer X item 5).
    """
    if not error:
        return None
    e = error.lower()
    if "timeout" in e:
        return "timeout"
    if e.startswith("dig exit"):
        return "dig_exit"
    if "short response" in e:
        return "short_response"
    return "other_error"


def compare_observations(
    obs: dict[str, dict[str, Any]],
    axes: Iterable[str] = SECURITY_AXES,
    *,
    null_aware: bool = True,
) -> dict[str, Any]:
    """Compare per-resolver observations on selected security-relevant axes.

    obs: {resolver_name: {rcode, answers, aa, ra, error, additional?, glue_cache_accept?}}

    When ``null_aware`` is True (default), a stand-in with no DNS message sets
    header/section axes to ⊥ and those axes do not enter the divergence count.
    ``hang_or_crash`` remains scored. Set ``null_aware=False`` for the legacy
    ungated triage view (can inflate D(p) via RCODE/AA/RA vs silence).
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
            "null_aware": null_aware,
            "all_null": not any(has_dns_message(obs[n]) for n in names),
        }

    message_present = {n: has_dns_message(obs[n]) for n in names}
    all_null = not any(message_present.values())

    def defined(name: str, axis: str) -> bool:
        if not null_aware:
            return True
        if axis == "hang_or_crash":
            return True
        if axis in NULL_GATED_AXES and not message_present[name]:
            return False
        return True

    divergences: list[dict[str, Any]] = []
    gated_skipped: list[dict[str, Any]] = []
    base = names[0]
    base_obs = obs[base]

    for other in names[1:]:
        o = obs[other]
        for axis in ("rcode", "aa", "ra", "glue_cache_accept"):
            if axis not in axis_set:
                continue
            if not (defined(base, axis) and defined(other, axis)):
                if null_aware and axis in NULL_GATED_AXES:
                    gated_skipped.append(
                        {
                            "axis": axis,
                            "left": base,
                            "right": other,
                            "reason": "null_response_undefined",
                        }
                    )
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
            if not (defined(base, "answers") and defined(other, "answers")):
                if null_aware:
                    gated_skipped.append(
                        {
                            "axis": "answers",
                            "left": base,
                            "right": other,
                            "reason": "null_response_undefined",
                        }
                    )
            elif normalize_answers(base_obs.get("answers")) != normalize_answers(
                o.get("answers")
            ):
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
            if not (defined(base, "additional") and defined(other, "additional")):
                if null_aware:
                    gated_skipped.append(
                        {
                            "axis": "additional",
                            "left": base,
                            "right": other,
                            "reason": "null_response_undefined",
                        }
                    )
            else:
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
            if classify_failure(base_obs.get("error")) != classify_failure(o.get("error")):
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
        "null_aware": null_aware,
        "message_present": message_present,
        "all_null": all_null,
        "gated_skipped": gated_skipped,
    }


def delta_divergence(pin: dict[str, Any], baseline: dict[str, Any]) -> dict[str, Any]:
    """Baseline-relative divergence, gated on (axis, value-pair) not axis name alone.

    Subtracting a baseline axis by name only (as printed by hand in the manuscript)
    can mask a polarity change: if an axis stays divergent at baseline and under the
    adversary but which side asserts it flips, that is a new, adversary-caused
    disagreement, not the same passthrough-default noise. Match on the full
    (axis, left_value, right_value) tuple instead — only an identical value-pair at
    baseline is treated as already-known.

    ``pin`` and ``baseline`` are ``compare_observations(...)`` results for the same
    resolver pairing (so "left"/"right" identity — the alphabetically-sorted base
    role — is consistent between the two calls).
    """

    def hashable(v: Any) -> Any:
        return tuple(v) if isinstance(v, list) else v

    def key(d: dict[str, Any]) -> tuple:
        return (d["axis"], hashable(d.get("left_value")), hashable(d.get("right_value")))

    baseline_keys = {key(d) for d in baseline.get("divergences", [])}
    delta = [d for d in pin.get("divergences", []) if key(d) not in baseline_keys]
    return {
        "delta_divergence_count": len(delta),
        "delta_divergences": delta,
        "baseline_axes": sorted({d["axis"] for d in baseline.get("divergences", [])}),
    }
