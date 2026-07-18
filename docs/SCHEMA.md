# Profile schema (v0)

Profiles are schema-first: new adversarial cases should land as JSON under `profiles/` without changing harness code (beyond optional injector plugins later).

## Required top-level fields

| Field | Type | Notes |
| --- | --- | --- |
| `id` | string | Stable ID, e.g. `P-SMOKE-AGREE` |
| `intent` | string | One-line purpose |
| `status` | string | `active` · `scaffold` · `deferred-os-layer` |
| `layer` | string | `application` · `os` |
| `adversary` | object | position / capability / win_condition |
| `dnssec_posture` | object | **required** — see below |
| `query` | object | `name`, `type` |
| `expect` | object | Profile-specific expectations |
| `class_hint` | string | Guidance for triage, not a finding |

## Required `adversary` object

| Field | Type |
| --- | --- |
| `position` | `none` · `on-path` · `off-path` · `malicious-but-trusted-upstream` |
| `capability` | string or string[] |
| `win_condition` | string |

## Required `dnssec_posture` object

Unbound validates by default; dnsmasq does not unless configured. Pin the posture so divergences are design choices, not accidents.

| Field | Type | Notes |
| --- | --- | --- |
| `mode` | `matched` · `deliberately_mismatched` | Matched = same validation intent for this profile |
| `unbound` | string | e.g. `off-lab-zone` · `validate` · `default-strict` |
| `dnsmasq` | string | e.g. `off` · `validate-with-trust-anchor` |
| `notes` | string | Why this posture for this profile |

Smoke must use `mode: matched` with both resolvers non-validating for the lab zone.

## Optional fields

| Field | Notes |
| --- | --- |
| `isolation` | For OS-layer: `runner`, `kernel`, `icmp_ratelimit_scope` (`per-netns` · `host-global` · `unverified`) |
| `notes` | Human notes |
| `injector` | Plugin id when MITM required |
| `references` | Literature mapping (measurement, not discovery claim) |

## Example skeleton

```json
{
  "id": "P-EXAMPLE",
  "intent": "…",
  "status": "scaffold",
  "layer": "application",
  "adversary": {
    "position": "malicious-but-trusted-upstream",
    "capability": ["crafted DNS response content in ADDITIONAL section"],
    "win_condition": "One resolver caches/uses out-of-bailiwick glue; the other ignores or SERVFAILs"
  },
  "dnssec_posture": {
    "mode": "matched",
    "unbound": "off-lab-zone",
    "dnsmasq": "off",
    "notes": "Matched non-validating so bailiwick logic is not confounded by DNSSEC defaults"
  },
  "query": { "name": "www.lab.stackdiff.", "type": "A" },
  "expect": {},
  "class_hint": "A_or_B_after_analysis"
}
```

## Validation rules

- `layer: os` + `status: active` ⇒ schema error until isolation criteria in `SCOPE-ISOLATION.md` are met.  
- Missing `dnssec_posture` ⇒ schema error.  
- `dnssec_posture.mode` must be `matched` or `deliberately_mismatched`.
