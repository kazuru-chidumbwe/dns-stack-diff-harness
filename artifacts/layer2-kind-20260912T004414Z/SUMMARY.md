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

## Digests

- Artifact tree SHA index: see `SHA256SUMS.txt`
- Combined adversarial digs fingerprint: `1804eecb393e14328e5109c38a69f852d070773b8fc8df044d50246eb9d6765e`

## How to read

Compare NodeLocal vs CoreDNS answers/ADDITIONAL/RCODE/FailureMode under each mode.
Passthrough is the agreeing control. additional-glue / malformed-truncate are load-bearing L2 pins.
