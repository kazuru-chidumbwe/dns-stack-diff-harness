#!/usr/bin/env bash
# Install NodeLocal DNSCache on Kind and probe consecutive hops (Layer 1).
# Usage on Lab Test Server:
#   KUBECTL='docker exec kosv-control-plane kubectl' ./scripts/layer1_kind_pins.sh
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KUBECTL="${KUBECTL:-kubectl}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ROOT/artifacts/layer1-kind-$STAMP"
mkdir -p "$OUT"

echo "L1: applying NodeLocal DNSCache manifests"
$KUBECTL apply -f "$ROOT/deploy/k8s/nodelocaldns.yaml" | tee "$OUT/apply.txt"

echo "L1: waiting for DaemonSet"
for i in $(seq 1 60); do
  ready="$($KUBECTL -n kube-system get ds node-local-dns -o jsonpath='{.status.numberReady}' 2>/dev/null || echo 0)"
  desired="$($KUBECTL -n kube-system get ds node-local-dns -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo 1)"
  echo "  ready=$ready desired=$desired"
  if [[ "$ready" == "$desired" && "$ready" != "0" ]]; then
    break
  fi
  sleep 5
done

$KUBECTL -n kube-system get ds,pods -l k8s-app=node-local-dns -o wide | tee "$OUT/nodelocal-pods.txt"
$KUBECTL -n kube-system get pods -l k8s-app=kube-dns -o wide | tee "$OUT/coredns-pods.txt"

# Probe from a disposable pod (matched non-validating — no dnssec plugin)
Q="kubernetes.default.svc.cluster.local"
cat >"$OUT/probe-job.yaml" <<EOF
apiVersion: v1
kind: Pod
metadata:
  name: stackdiff-dns-probe
  namespace: default
spec:
  restartPolicy: Never
  containers:
  - name: dig
    image: instrumentisto/dig:latest
    command: ["sleep", "120"]
EOF
$KUBECTL delete pod stackdiff-dns-probe --ignore-not-found >/dev/null 2>&1 || true
$KUBECTL apply -f "$OUT/probe-job.yaml"
$KUBECTL wait --for=condition=Ready pod/stackdiff-dns-probe --timeout=90s

{
  echo "=== dig NodeLocal 169.254.20.10 ==="
  $KUBECTL exec stackdiff-dns-probe -- dig @"169.254.20.10" "$Q" A +time=2 +tries=1 +noall +answer +comments || true
  echo "=== dig CoreDNS kube-dns 10.96.0.10 ==="
  $KUBECTL exec stackdiff-dns-probe -- dig @"10.96.0.10" "$Q" A +time=2 +tries=1 +noall +answer +comments || true
  echo "=== dig NodeLocal external (example.com) ==="
  $KUBECTL exec stackdiff-dns-probe -- dig @"169.254.20.10" example.com A +time=3 +tries=1 +noall +answer +comments || true
  echo "=== dig CoreDNS external ==="
  $KUBECTL exec stackdiff-dns-probe -- dig @"10.96.0.10" example.com A +time=3 +tries=1 +noall +answer +comments || true
} | tee "$OUT/digs.txt"

cat >"$OUT/SUMMARY.md" <<EOF
# Layer-1 Kind consecutive-hop pins ($STAMP)

- Cluster: Kind \`kosv-control-plane\`
- Hops: NodeLocal DNSCache \`169.254.20.10\` → CoreDNS kube-dns \`10.96.0.10\`
- DNSSEC: matched non-validating (default CoreDNS / node-cache; no validate plugin)
- Isolation: Kind CNI ≠ pair-mode Docker compose
- Adversarial MITM on upstream path: **not** established in this pin (cluster uses node resolv.conf upstream)

See digs.txt for raw probes.
EOF

$KUBECTL delete pod stackdiff-dns-probe --ignore-not-found >/dev/null 2>&1 || true
echo "L1 artifact: $OUT"
