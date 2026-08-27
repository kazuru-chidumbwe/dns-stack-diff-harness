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
| Vendor vector → `glue_cache_accept=true` on **1.24.0** | Positive control OK → boundary grid interpretable |
| Vendor vector → still false on 1.24.0 after iterator + prime | Harness plumbing bug (localize); not “resolver stability” |
| Iterator topology cannot arm CVE at all | Bounded finding: pair-mode does not reproduce iterator-path poisoning — **no** checksummed-stability claim |

## Do not

- Interpret 1.24.1 / 1.24.2 `false` as “fixed” before PC-3.  
- Report Layer-2 “checksummed stability” without a validated vulnerable true.  
- Treat additional-glue-only or forwarder-topology nulls as CVE currency.
