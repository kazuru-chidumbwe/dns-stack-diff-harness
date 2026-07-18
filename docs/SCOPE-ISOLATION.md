# Scope / Isolation Model

This document exists because containerization is a **threat to validity** for OS-layer DNS attacks. It is not optional prose. Klein and SAD DNS are **not** the same claim.

## Executive decision (v0)

| Layer / attack class | Isolation requirement | StackDiff status |
| --- | --- | --- |
| **Application-layer** divergence (RCODE, RRset, flags, cache accept/reject, DNSSEC outcome when posture is pinned, hang/crash) | Plain Docker / shared kernel **acceptable** | **In scope (v0)** |
| **Klein-class** shared `prandom` / cross-layer port–flow-label–IP-ID prediction | Below netns; shared across containers on one host | **Deferred** — Firecracker / Kata / full VM |
| **SAD DNS-class** ICMP side channel | See two-change model below (randomization ≠ netns) | **Deferred until lab `uname -r` + package recorded** |

## Oracle axes (full vs smoke)

| Axis | Full oracle (v0 design) | Smoke pass criterion (`P-SMOKE-AGREE`) |
| --- | --- | --- |
| RCODE | Yes | **Yes (gate)** — must be `NOERROR` |
| RRset / answers | Yes | **Yes (gate)** — must match and contain `203.0.113.10` |
| Flags (AA/RA) | Yes (recorded) | Informational only — not fail |
| Cache accept/reject | Yes (when observable) | N/A on smoke |
| Hang/crash | Yes | **Yes (gate)** — neither side may hard-error |
| Class A/B/C | Triage label | **C** if smoke fails — harness bug, not a finding |

**Harness-failure rule:** any smoke-axis mismatch ⇒ stop; do not publish as Class A/B.

## Klein — why Docker does not isolate it

Klein analyzes the Linux kernel’s shared **`prandom`** generator as consumed by UDP source ports, IPv6 flow labels, and IPv4 IDs. The paper demonstrates the attack can be mounted **locally across Linux users and across containers** on the same host. Netns alone is insufficient.

Reference: Amit Klein, *Cross Layer Attacks and How to Use Them…* (arXiv:2012.07432).

## SAD DNS — two changes, not one cutoff

SAD DNS (CVE-2020-25705) uses ICMP rate limiting as a **side channel** for ephemeral-port inference. Treat mitigations separately.

### 1. Primary mitigation — randomize the limiter (≈5.10+)

| Field | Value |
| --- | --- |
| Commit (full) | [`b38e7819cae946e2edf869e604af1e65a5d241c5`](https://github.com/torvalds/linux/commit/b38e7819cae946e2edf869e604af1e65a5d241c5) |
| Subject | `icmp: randomize the global rate limiter` |
| Mainline | **5.10+** |
| Backports | Wide stable/LTS backports (distro-dependent) |

Adds noise so the token bucket is no longer a clean oracle. **This is the primary SAD DNS fix.** See [saddns.net](https://www.saddns.net/).

### 2. Isolation improvement — per-netns token-bucket state (v6.11 → v6.12 tags)

Verified 2026-07-18 against **torvalds/linux** tags (`net/ipv4/icmp.c`):

| Tag | `icmp_global_allow` | Token-bucket state |
| --- | --- | --- |
| **v6.11** | `bool icmp_global_allow(void)` | Host-wide `icmp_global.credit` / `stamp` |
| **v6.12** | `bool icmp_global_allow(struct net *net)` | Per-netns `net->ipv4.icmp_global_*` |

| Field | Value |
| --- | --- |
| Commit (full) | [`b056b4cd9178f7a1d5d57f7b48b073c29729ddaa`](https://github.com/torvalds/linux/commit/b056b4cd9178f7a1d5d57f7b48b073c29729ddaa) |
| Subject | `icmp: move icmp_global.credit and icmp_global.stamp to per netns storage` |
| Author date | 2024-08-29 |

Affects whether **two Docker containers share the msgs-per-sec bucket**. Not a substitute for randomization.

### Distro reality

| Shape | Typical implication |
| --- | --- |
| Mainline **5.10–6.11** (+ LTS with randomization backport) | Side channel noised; bucket often still **host-wide** |
| Mainline **≥ 6.12** | Noised + **per-netns** bucket |
| Ubuntu 24.04 LTS / many enterprise kernels through 2025–early 2026 | Usually randomized via backport; **often still &lt; 6.12** — verify; do not assume per-netns |

**Lab rule:** record `uname -r`, distro kernel package, and (if claiming netns isolation) confirm `icmp_global_allow` shape. Prefer full commit URLs.

## DNSSEC posture

Unbound validates by default; dnsmasq does not unless configured. Every profile must declare `dnssec_posture`. Smoke = matched non-validating. See `SCHEMA.md` / `THREAT-MODEL.md`.

## What v0 measures

Application-layer agreement under pinned DNSSEC posture.

**Oracle validation step:** `P-SMOKE-AGREE` runs Unbound **forward-only** against the same lab auth as dnsmasq so gate one isolates comparator correctness from iterative recursion. Full recursive Unbound = DNS-02+.

## What v0 does not measure (yet)

- Klein-class shared-`prandom` under plain Docker  
- SAD DNS-class claims without a pinned kernel / package story  
- “Container A resists Klein better than B” on shared-kernel Docker  

## Upgrade path

| Target | Before `status: active` |
| --- | --- |
| Klein-class | Firecracker / Kata / full VM; document kernel; re-smoke |
| SAD DNS-class | `uname -r` + package; state randomization backport status; state msgs-per-sec netns shape |
| Path mode | Pair-mode oracle trusted; then chain hops |

## Deferred profile IDs

| ID | Class | Status |
| --- | --- | --- |
| `P-OS-KLEIN-PRNG-DEFERRED` | Klein / shared prandom | `deferred-os-layer` |
| `P-OS-SAD-DNS-ICMP-DEFERRED` | SAD DNS | `deferred-os-layer` until lab kernel story pinned |
