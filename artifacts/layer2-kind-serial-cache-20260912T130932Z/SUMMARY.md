# Layer-2 Kind SERIAL cache-staleness experiment (20260912T130932Z)

**A genuine consecutive-hop chain, not a parallel comparison.** Built in response to
external review flagging that no experiment in this paper actually measured
adjacent-hop path behavior — every prior pin queries two stand-ins independently
under a shared upstream condition. This one does not: a single query path
traverses NodeLocal -> CoreDNS -> auth, and NodeLocal's cache (its real
production role in Kubernetes) is enabled, not bypassed.

- Host: Lab Test Server `lab`
- Cluster: Kind `kosv` / `kosv-control-plane`
- Chain: NodeLocal DNSCache `169.254.20.10` (cache 20s) -> CoreDNS kube-dns
  `10.96.0.10` (no cache) -> auth CoreDNS (ClusterIP, zone-served, no MITM)
- Query: `www.lab.stackdiff.` A
- No adversarial injector. The "change" is a real authoritative zone-record
  update (`www` A: `203.0.113.20` -> `203.0.113.21`), analogous to promoting a
  configuration or record change at an upstream DNS role.
- Claim fence: laboratory Kind path under pinned zone; measures cache-induced
  propagation lag only; not a production Kubernetes replay.

## Result

| Stage | NodeLocal | CoreDNS | D(answer) |
| --- | --- | --- | ---: |
| Pre-change | 203.0.113.20 | 203.0.113.20 | 0 |
| Immediately post-change | 203.0.113.20 (stale) | 203.0.113.21 (fresh) | 1 |
| After cache TTL elapses | 203.0.113.21 | 203.0.113.21 | 0 |

**Observed propagation lag: ~30.3 s** (cache TTL 20s + query/rollout timing) from
the authoritative change to NodeLocal reflecting it. CoreDNS reflected the
change on its very next query (uncached).

## Why this is a genuine serial-hop finding, not a repeat of the retired pass-through pack

The earlier `layer2-kind-20260912T004414Z` pack was a bare relay: NodeLocal had
no independent behavior, so "agreement" there just meant NodeLocal echoed
whatever CoreDNS returned. Here, NodeLocal's cache is exactly the kind of
independent, hop-specific state a true chain can have and a parallel
comparison structurally cannot observe: the divergence at the "immediately
post-change" stage is caused by *seriality itself* (a caching layer sitting in
front of an upstream that just changed), not by comparing two unrelated
implementations under one shared condition.

## Digests

- Artifact tree SHA index: see `SHA256SUMS.txt` — verify with `sha256sum -c SHA256SUMS.txt`
- Load-bearing transcripts: `digs/pre-nodelocal.txt`, `digs/post-change-nodelocal.txt`,
  `digs/post-change-coredns.txt`, `digs/reconverged-nodelocal.txt`
- Decision record: `decision.json` (machine-readable stages + timestamps + propagation lag)
