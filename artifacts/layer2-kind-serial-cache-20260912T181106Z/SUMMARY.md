# Layer-2 Kind SERIAL cache-staleness experiment (20260912T181106Z)

**Re-run of `layer2-kind-serial-cache-20260912T130932Z` with active polling, to
turn an upper bound into a measurement.** External review (Reviewer X) correctly
identified that the first pack's `propagation_lag_observed_s` (~30.3s) was not a
measurement: the script slept `CACHE_TTL+8`s from the *change*, then took one
sample, so the reported number was "time we waited," not "time it actually
took." The cache entry NodeLocal served was populated *before* the change (at
the pre-change query), so its true expiry — and thus the real staleness
window — was `cache_ttl_s - (t_promote - t_pre_nodelocal)` after the change,
not `cache_ttl_s` after the change. The first pack's own `decision.json`
confirms this: the true window was ~15.1s; the reported ~30.3s was ~2x that.

This pack fixes it by polling NodeLocal every ~1s starting immediately after
promotion until the new value is observed, recording first-observation time.
It also computes an independent mechanistic prediction from the TTL and
pre-change query timestamp, so the artifact self-checks: measured and
predicted should agree within one poll interval.

- Host: Lab Test Server `lab`
- Cluster: Kind `kosv` / `kosv-control-plane`
- Chain: NodeLocal DNSCache `169.254.20.10` (cache 20s) -> CoreDNS kube-dns
  `10.96.0.10` (no cache) -> auth CoreDNS (ClusterIP, zone-served, no MITM)
- Query: `www.lab.stackdiff.` A
- No adversarial injector. The "change" is a real authoritative zone-record
  update (`www` A: `203.0.113.20` -> `203.0.113.21`).
- Claim fence: laboratory Kind path under pinned zone; measures cache-induced
  propagation lag only; not a production Kubernetes replay.

## Result

| Stage | NodeLocal | CoreDNS | D(answer) |
| --- | --- | --- | ---: |
| Pre-change | 203.0.113.20 | 203.0.113.20 | 0 |
| Immediately post-change | 203.0.113.20 (stale) | 203.0.113.21 (fresh) | 1 |
| Reconverged (poll #13) | 203.0.113.21 | 203.0.113.21 | 0 |

**Measured propagation lag: 15.65s** (first NodeLocal poll returning the new
value, ~1s-resolution polling from the moment of promotion).
**Predicted from TTL: 15.54s** (cache populated at the pre-change query,
20s TTL, minus elapsed time from that query to promotion). The two agree
within 0.11s, well inside one poll interval, which is the cross-check this
pack was built to support. CoreDNS reflected the change on its very next
query (uncached).

## Why the measured and predicted values differ from the first pack's number

The first pack's ~30.3s conflated the sleep duration with the propagation
lag. Cache TTL alone does not equal propagation lag unless the change happens
at the instant the cache entry is populated; here the entry was already ~4.5s
old when the change was promoted, so only the *remaining* TTL — not the full
20s — was the staleness window. Both numbers are preserved in this pack's
`decision.json` for anyone re-deriving the arithmetic.

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

- Artifact tree SHA index: see `SHA256SUMS.txt` (27 files, `run.log` included)
  — verify with `sha256sum -c SHA256SUMS.txt`
- Load-bearing transcripts: `digs/pre-nodelocal.txt`, `digs/post-change-nodelocal.txt`,
  `digs/post-change-coredns.txt`, `digs/poll-nodelocal-13.txt` (first stale->fresh
  observation), `digs/reconverged-coredns.txt`
- Decision record: `decision.json` (machine-readable stages + timestamps +
  measured and predicted propagation lag + poll attempt count)
- Superseded by this pack, kept for history: `layer2-kind-serial-cache-20260912T130932Z`
  (same chain/topology; only the timing methodology changed)
