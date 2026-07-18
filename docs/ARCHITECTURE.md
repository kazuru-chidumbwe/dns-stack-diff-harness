# Architecture — StackDiff v0

## Goal

**Pair mode (v0):** under identical application-layer upstream conditions, with pinned DNSSEC posture, do two resolver implementations agree on smoke axes (RCODE + RRset)?

**Path mode (later):** chain stub → node-local → CoreDNS → upstream; same profiles and oracle apply to consecutive hops once the pair-mode oracle is trusted.

## Role stand-ins (why Unbound + dnsmasq)

| Binary | Path role approximated |
| --- | --- |
| dnsmasq | Local forwarder/cache ≈ NodeLocal DNSCache / systemd-resolved |
| Unbound | Full recursive / validating ≈ CoreDNS recursive or upstream resolver |

Standalone binaries first; containerized CoreDNS / systemd-resolved later so harness bugs are not conflated with path-specific behavior.

## Diagram (pair mode)

```text
Profile corpus ──────► dig / client
(YAML/JSON,                 │
 threat-model + DNSSEC      │ same query, same injected
 posture fields)            │ upstream behavior
                  ┌─────────┴─────────┐
                  ▼                   ▼
             ┌─────────┐         ┌─────────┐
             │ Unbound │         │ dnsmasq │
             └────┬────┘         └────┬────┘
                  └─────────┬─────────┘
                            ▼
                 ┌──────────────────────────┐
                 │   Divergence oracle      │
                 │ RCODE · RRset · flags    │
                 │ cache · hang/crash       │
                 │ Class A/B/C              │
                 │ smoke gate ⊂ full axes   │
                 └──────────────────────────┘
                            ▲
                  ┌─────────┴─────────┐
                  │ Auth / MITM stub  │
                  │ (controlled lab)  │
                  └───────────────────┘
```

Smoke uses Unbound **forward-only** against lab auth — this is the **oracle validation step**. Full recursive Unbound = DNS-02+.

## Non-goals (v0)

- Peer-fuzzing at ResolFuzz / ResolverFuzz scale  
- Klein-class shared-prandom measurement under plain Docker  
- SAD DNS-class ICMP profiles until netns verification is recorded  
- Invented finding counts  

## Docs that must stay first-class

| Doc | Why |
| --- | --- |
| [`THREAT-MODEL.md`](THREAT-MODEL.md) | Adversary fields + DNSSEC posture |
| [`SCOPE-ISOLATION.md`](SCOPE-ISOLATION.md) | Klein vs SAD DNS split; Docker validity |
| [`SCHEMA.md`](SCHEMA.md) | Profile contract |

## Smoke rule

Divergence on `P-SMOKE-AGREE` (RCODE/RRset) ⇒ **Class C / harness bug**, not a security finding.
