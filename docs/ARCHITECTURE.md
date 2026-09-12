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

## Kind L2 topology fix — parallel forwarding (DONE, `artifacts/layer2-kind-parallel-20260912T112004Z/`)

`artifacts/layer2-kind-20260912T004414Z/` (superseded, kept for history) shipped a
**serial** chain, not the pair-mode topology the rest of this harness uses:
`nodelocal-corefile-new`'s `lab.stackdiff:53` block forwarded to `10.96.200.251`
(`kube-dns-upstream` → CoreDNS), and CoreDNS's own `lab.stackdiff:53` block forwarded
on to the MITM. NodeLocal never queried the MITM independently — it relayed whatever
CoreDNS already returned. Reading that as two independent stand-ins agreeing was
wrong: it was a pass-through fidelity check, not path agreement.

**Fix, executed 12 Sep 2026 on Lab Test Server** (`scripts/layer2_kind_adversarial_parallel.sh`):
point NodeLocal's `lab.stackdiff:53` `forward` directly at the MITM service, same
target as CoreDNS's own block, instead of at CoreDNS:

```corefile
lab.stackdiff:53 {
    errors
    reload
    loop
    bind 169.254.20.10 10.96.0.10
    forward . <mitm-clusterip>
}
```

Both hops now query the MITM independently, restoring the Section III-D invariant
("both stand-ins forward to the same MITM/auth path") every other pin already
satisfies. Result (`artifacts/layer2-kind-parallel-20260912T112004Z/SUMMARY.md`):
passthrough and additional-glue fully agree; **malformed-truncate genuinely
diverges** — NodeLocal gets no message at all (hard client timeout), CoreDNS gets a
real `FORMERR` response. Null-aware, that is $D_{\mathrm{null}}=1$ on FailureMode,
the same divergence shape as the August Unbound-vs-dnsmasq malformed pin, now
replicated on an independent resolver pair in a different environment
(Kubernetes, not Docker Compose).

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
