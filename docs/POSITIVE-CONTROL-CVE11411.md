# Positive control — CVE-2025-11411 / promiscuous-NS (measurement validity)

**Status:** GATE — required before interpreting Unbound 1.24.1 / 1.24.2 cells  
**Sponsor lock:** `CURRENT-WORK/notes/sponsor/sponsor-lock-stackdiff-positive-control-2026-08-27.md`

## Why

`glue_cache_accept=false` on known-vulnerable Unbound (≤1.24.0) means the harness has **not** demonstrated it can arm the CVE path. A later `false` on a fixed build is then uninterpretable (fix vs unarmed injector).

## Known lab defect (27 Aug pin)

[`deploy/resolvers/unbound/unbound-via-mitm.conf`](../deploy/resolvers/unbound/unbound-via-mitm.conf) uses:

```yaml
forward-zone:
    name: "."
    forward-addr: 172.30.0.11   # MITM
```

That is a **forwarder** path. CVE-2025-11411 is an **iterator** delegation-cache bug. Forwarding to the MITM skips the trust computation the advisory describes.

## Required conditions

1. Unbound **iterates** (MITM on authority / delegation path, not wholesale forwarder).  
2. **Prime** an existing delegation for `lab.stackdiff`, then inject on a later **NOERROR-positive** reply.  
3. NS owner-name aligned to the **zone cut** Unbound tracks; ADDITIONAL A for follow-up probe may stay out-of-zone (`ns.evil.test`).

## Vendor vectors (do this first)

Port packet shapes from NLnet regression diffs shipped with the fixes:

- `patch_CVE-2025-11411_option_tests.diff` (around 1.24.1)
- `patch_CVE-2025-11411_2_wtests.diff` (around 1.24.2)

Do **not** reverse-engineer solely from advisory prose.

## Pass / fail

| Outcome | Meaning |
| --- | --- |
| Vendor-shaped inject → `glue_cache_accept=true` on **1.24.0** (iterator) | Positive control OK → boundary grid interpretable |
| Still false on 1.24.0 after iterator + vendor vector | Harness plumbing bug (localize); not “resolver stability” |
| Iterator topology cannot arm CVE at all | Bounded finding: pair-mode does not reproduce iterator-path poisoning — **no** checksummed-stability claim |

## Lab command

```bash
cd /opt/atlas/repos/dns-stack-diff-harness   # Lab Test Server
python3 scripts/positive_control_cve11411.py --image l33tlamer/unbound-recursive:1.24.0
# artifact: artifacts/positive-control-<UTC>/result.json
```

Compose files: `compose.yaml` + `compose.adversarial.yaml` + `compose.iterate-pc.yaml`.  
Vendor materials: `vendor/cve-2025-11411/` (NLnet advisory + diffs).

## Lab status (27 Aug evening)

Iterator + MITM-on-path + vendor-shaped AUTHORITY NS: **poison on wire (`1/2/2`), still no cache accept on 1.24.0.** See programme note [`GATE-POSITIVE-CONTROL-CVE11411-2026-08-27.md`](../../../CURRENT-WORK/DNS%20Project/internal/GATE-POSITIVE-CONTROL-CVE11411-2026-08-27.md). Next: referral-chain topology matching `iter_scrub_promiscuous.rpl` (stub root only), not stub of the victim zone.
