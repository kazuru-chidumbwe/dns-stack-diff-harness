# Layer-2 Kind adversarial consecutive-hop pins, PARALLEL topology (20260912T112004Z)

- Host: Lab Test Server `lab`
- Cluster: Kind `kosv` / `kosv-control-plane`
- Hops: NodeLocal DNSCache `169.254.20.10` and CoreDNS kube-dns `10.96.0.10` **each forward `lab.stackdiff` directly to the MITM independently** (parallel pair-mode topology — fixes the serial NodeLocal->CoreDNS->MITM chain in `layer2-kind-20260912T004414Z`; see `docs/ARCHITECTURE.md`).
- Query: `www.lab.stackdiff.` A
- Modes: passthrough · additional-glue · malformed-truncate
- DNSSEC: matched non-validating
- Isolation: Kind CNI / hostNetwork NodeLocal; application-layer MITM in-cluster
- Control: `example.com` via NodeLocal should **not** traverse MITM (node upstream)
- Claim fence: laboratory Kind path under pinned zone; **not** production Kubernetes; **not** OS-layer channels

## Digests

- Artifact tree SHA index: see `SHA256SUMS.txt` — verify with `sha256sum -c SHA256SUMS.txt`
- Load-bearing dig transcripts: `modes/additional-glue/digs-pin.txt` and `modes/malformed-truncate/digs-pin.txt` (per-file SHAs in `SHA256SUMS.txt`)

## How to read

Compare NodeLocal vs CoreDNS answers/ADDITIONAL/RCODE/FailureMode under each mode.
Unlike the prior serial pack, agreement or disagreement here is a genuine independent-hop
result: both NodeLocal and CoreDNS query the MITM on their own, comparable to the August
pair-mode pins.

- **Passthrough:** full agreement (identical RCODE/answer/AUTHORITY on both hops).
- **additional-glue:** full agreement (identical ANSWER + ADDITIONAL `ns.evil.test`->`198.51.100.66` on both hops). NodeLocal's dig log shows one transient `communications error ... timed out` before its retry succeeded — daemonset settle noise right after the Corefile reload, not a scored divergence; the final compared answer on both hops is identical.
- **malformed-truncate: genuine divergence.** NodeLocal gets no DNS message at all (`no servers could be reached` after both retries) — a hard client-side timeout. CoreDNS gets a real message: `status: FORMERR`. Null-aware, this is $D_{\mathrm{null}}=1$ on FailureMode (NodeLocal silent, CoreDNS message-bearing), the same divergence *shape* as the August Unbound-vs-dnsmasq malformed pin, replicated here on a different resolver pair (NodeLocal/CoreDNS) in a different environment (Kubernetes, not Docker Compose).

`example.com` via NodeLocal is a liveness control only (live Internet, not replayable) — not part of the scored comparison.
