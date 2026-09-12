# Layer-2 Kind adversarial consecutive-hop pins (20260912T004414Z)

- Host: Lab Test Server `lab`
- Cluster: Kind `kosv` / `kosv-control-plane`
- Hops: NodeLocal DNSCache `169.254.20.10` → CoreDNS kube-dns `10.96.0.10` → MITM → auth (`lab.stackdiff`)
- Query: `www.lab.stackdiff.` A
- Modes: passthrough · additional-glue · malformed-truncate
- DNSSEC: matched non-validating
- Isolation: Kind CNI / hostNetwork NodeLocal; application-layer MITM in-cluster
- Control: `example.com` via NodeLocal should **not** traverse MITM (node upstream)
- Claim fence: laboratory Kind path under pinned zone; **not** production Kubernetes; **not** OS-layer channels
- **Superseded:** NodeLocal forwards `lab.stackdiff` to CoreDNS, which forwards to the MITM (serial, not parallel) — NodeLocal never queries the MITM independently here, so hop agreement in this pack is a pass-through fidelity result, not independent-agreement. The parallel-topology re-run in `artifacts/layer2-kind-parallel-20260912T112004Z/` is the load-bearing L2 pack; this one is kept for history. See `docs/ARCHITECTURE.md`.

## Digests

- Artifact tree SHA index: see `SHA256SUMS.txt` — verify with `sha256sum -c SHA256SUMS.txt`
- Load-bearing dig transcripts: `modes/additional-glue/digs-pin.txt` and `modes/malformed-truncate/digs-pin.txt` (per-file SHAs in `SHA256SUMS.txt`)

## How to read

Compare NodeLocal vs CoreDNS answers/ADDITIONAL/RCODE/FailureMode under each mode.
Passthrough is the agreeing control. additional-glue / malformed-truncate are load-bearing L2 pins.
