# Architecture — StackDiff v0

## Goal

**Pair mode (v0):** under identical application-layer upstream conditions, with pinned DNSSEC posture, do two resolver implementations agree on smoke axes (RCODE + RRset)?

**Path mode (later):** chain stub → node-local → CoreDNS → upstream; same profiles and oracle apply to consecutive hops once the pair-mode oracle is trusted.

## Role stand-ins (why Unbound + CoreDNS-forwarder)

| Binary | Path role approximated |
| --- | --- |
| coredns_fwd | Local forwarder/cache ≈ NodeLocal DNSCache / systemd-resolved |
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

## Kind L2 topology fix — parallel forwarding (planned re-run)

`artifacts/layer2-kind-20260912T004414Z/` shipped a **serial** chain, not the pair-mode
topology the rest of this harness uses: `nodelocal-corefile-new`'s `lab.stackdiff:53`
block forwards to `10.96.200.251` (`kube-dns-upstream` → CoreDNS), and CoreDNS's own
`lab.stackdiff:53` block forwards on to the MITM (`10.96.104.126`). NodeLocal never
queries the MITM independently — it relays whatever CoreDNS already returned. Reading
that as two independent stand-ins agreeing is wrong: it's a pass-through fidelity
check (does NodeLocal relay adversarial content without stripping it?), not path
agreement. `docs/../artifacts/layer2-kind-20260912T004414Z/SUMMARY.md` now says so.

**Fix (one Corefile line, next Kind session on Lab Test Server):** point NodeLocal's
`lab.stackdiff:53` `forward` directly at the MITM service instead of at CoreDNS:

```corefile
lab.stackdiff:53 {
    errors
    reload
    loop
    bind 169.254.20.10 10.96.0.10
    forward . 10.96.104.126
}
```

(only the `forward` target line changes — from `10.96.200.251` to the MITM service
IP; confirm the current MITM ClusterIP with `kubectl get svc stackdiff-mitm` since it
is not guaranteed stable across reprovisions). Then re-apply the ConfigMap, restart
`node-local-dns` and `coredns`, and re-run the same three modes (`passthrough`,
`additional-glue`, `malformed-truncate`) against both `169.254.20.10` and
`10.96.0.10` directly. That restores the design invariant Section III-D states for
every other pin ("both stand-ins forward to the same MITM/auth path") and makes a
Kind agreement/disagreement result comparable to the August pair. Until this re-run
ships, the manuscript reports L2 as a pass-through fidelity observation only and does
not draw the August contrast from it.

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
| [`ADVERSARIAL.md`](ADVERSARIAL.md) | Adversarial runner + measurement-only rule |

## Smoke rule

Divergence on `P-SMOKE-AGREE` (RCODE/RRset) ⇒ **Class C / harness bug**, not a security finding.
