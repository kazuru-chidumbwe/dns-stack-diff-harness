# Layer-1 Kind consecutive-hop pins (20260904T231736Z)

- Host: Host B `test-server`
- Cluster: Kind `kosv` / `kosv-control-plane`
- Hops: NodeLocal DNSCache `169.254.20.10` → CoreDNS kube-dns `10.96.0.10`
- Probe: `dig` from Kind node (in-cluster probe image `instrumentisto/dig` ImagePullBackOff; busybox kind-load broken on this host)
- DNSSEC: matched non-validating
- Isolation: Kind CNI / hostNetwork NodeLocal ≠ pair-mode Docker compose
- Adversarial MITM on upstream path: **not** established

See digs.txt for raw probes.
