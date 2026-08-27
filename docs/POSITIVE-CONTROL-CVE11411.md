# Positive control — CVE-2025-11411 / promiscuous-NS (measurement validity)

**Status:** **PASSED** on Lab Test Server (2026-08-27) — required before interpreting Unbound 1.24.1 / 1.24.2 cells  
**Sponsor lock:** `CURRENT-WORK/notes/sponsor/sponsor-lock-stackdiff-positive-control-2026-08-27.md`  
**Programme note:** [`GATE-POSITIVE-CONTROL-CVE11411-2026-08-27.md`](../../../CURRENT-WORK/DNS%20Project/internal/GATE-POSITIVE-CONTROL-CVE11411-2026-08-27.md)

## Why

`delegation_poisoned=false` on known-vulnerable Unbound (≤1.24.0) means the harness has **not** demonstrated it can arm the CVE path. A later `false` on a fixed build is then uninterpretable (fix vs unarmed injector).

## Known lab defect (resolved)

[`deploy/resolvers/unbound/unbound-via-mitm.conf`](../deploy/resolvers/unbound/unbound-via-mitm.conf) uses `forward-zone name: "."` → **forwarder** path. CVE-2025-11411 is an **iterator** delegation-cache bug.

Stubbing **`lab.stackdiff.`** directly also skips the referral→update path. Use parent stub + child referral (`unbound-via-mitm-iterate.conf` + `compose.iterate-pc.yaml`).

## Required conditions (met)

1. Unbound **iterates** (parent stub; MITM on child authority path).  
2. Child NS learned by **referral**, then **pollute1 REPLACE** AUTHORITY NS on a later positive A reply.  
3. Detect via `check.lab.stackdiff.` answered by attacker (`198.51.100.99`), not auth.

## Vendor vectors

Ported from NLnet:

- `vendor/cve-2025-11411/patch_CVE-2025-11411_option_tests.diff` — `iter_scrub_promiscuous.rpl` **pollute1**
- MITM mode `authority-ns-glue` implements AUTHORITY-only replace (no ADDITIONAL on inject)

## Lab results (27 Aug)

| Image | Pass |
| --- | --- |
| 1.24.0 | **true** (injector armed) |
| 1.24.1 | false (fix holds) |
| 1.24.2 | false (fix holds) |

Ready probe is a child-zone A under inject (may arm before named prime); gate signal is `check` → attacker.

```bash
cd /opt/atlas/repos/dns-stack-diff-harness   # Lab Test Server
python3 scripts/positive_control_cve11411.py --image l33tlamer/unbound-recursive:1.24.0
# artifact: artifacts/positive-control-<UTC>/result.json
```

Compose: `compose.yaml` + `compose.adversarial.yaml` + `compose.iterate-pc.yaml`.
