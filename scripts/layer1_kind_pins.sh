#!/usr/bin/env bash
# Install NodeLocal DNSCache on Kind and probe consecutive hops (Layer 1).
# Usage:
#   KUBECONFIG=... ./scripts/layer1_kind_pins.sh
#   KIND_NODE=kosv-control-plane ./scripts/layer1_kind_pins.sh   # enables node-dig fallback
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KUBECTL="${KUBECTL:-kubectl}"
KIND_NODE="${KIND_NODE:-kosv-control-plane}"
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

Q="kubernetes.default.svc.cluster.local"
PROBE_IMAGE="${PROBE_IMAGE:-busybox:1.36}"
PROBE_MODE="busybox-nslookup"

run_node_dig() {
  PROBE_MODE="control-plane-dig"
  echo "probe-mode: $PROBE_MODE" | tee "$OUT/probe-mode.txt"
  if ! docker exec "$KIND_NODE" which dig >/dev/null 2>&1; then
    docker exec "$KIND_NODE" bash -lc 'apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq dnsutils' || true
  fi
  {
    echo "=== dig NodeLocal 169.254.20.10 ==="
    docker exec "$KIND_NODE" dig @"169.254.20.10" "$Q" A +time=2 +tries=1 +noall +answer +comments || true
    echo "=== dig CoreDNS kube-dns 10.96.0.10 ==="
    docker exec "$KIND_NODE" dig @"10.96.0.10" "$Q" A +time=2 +tries=1 +noall +answer +comments || true
    echo "=== dig NodeLocal external (example.com) ==="
    docker exec "$KIND_NODE" dig @"169.254.20.10" example.com A +time=3 +tries=1 +noall +answer +comments || true
    echo "=== dig CoreDNS external ==="
    docker exec "$KIND_NODE" dig @"10.96.0.10" example.com A +time=3 +tries=1 +noall +answer +comments || true
  } | tee "$OUT/digs.txt"
}

# Prefer in-cluster busybox; fall back to dig on the Kind node.
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
    image: ${PROBE_IMAGE}
    imagePullPolicy: IfNotPresent
    command: ["sleep", "180"]
EOF
$KUBECTL delete pod stackdiff-dns-probe --ignore-not-found >/dev/null 2>&1 || true
$KUBECTL apply -f "$OUT/probe-job.yaml"
if $KUBECTL wait --for=condition=Ready pod/stackdiff-dns-probe --timeout=90s; then
  echo "probe-mode: $PROBE_MODE" | tee "$OUT/probe-mode.txt"
  {
    echo "=== nslookup NodeLocal 169.254.20.10 ==="
    $KUBECTL exec stackdiff-dns-probe -- nslookup "$Q" 169.254.20.10 || true
    echo "=== nslookup CoreDNS kube-dns 10.96.0.10 ==="
    $KUBECTL exec stackdiff-dns-probe -- nslookup "$Q" 10.96.0.10 || true
    echo "=== nslookup NodeLocal external (example.com) ==="
    $KUBECTL exec stackdiff-dns-probe -- nslookup example.com 169.254.20.10 || true
    echo "=== nslookup CoreDNS external ==="
    $KUBECTL exec stackdiff-dns-probe -- nslookup example.com 10.96.0.10 || true
  } | tee "$OUT/digs.txt"
else
  echo "L1: in-cluster probe not Ready; falling back to node dig ($KIND_NODE)"
  $KUBECTL describe pod stackdiff-dns-probe 2>/dev/null | tee "$OUT/probe-describe.txt" || true
  $KUBECTL delete pod stackdiff-dns-probe --ignore-not-found >/dev/null 2>&1 || true
  run_node_dig
fi

cat >"$OUT/SUMMARY.md" <<EOF
# Layer-1 Kind consecutive-hop pins ($STAMP)

- Cluster: Kind \`$KIND_NODE\`
- Hops: NodeLocal DNSCache \`169.254.20.10\` → CoreDNS kube-dns \`10.96.0.10\`
- Probe mode: $PROBE_MODE
- DNSSEC: matched non-validating (default CoreDNS / node-cache; no validate plugin)
- Isolation: Kind CNI ≠ pair-mode Docker compose
- Adversarial MITM on upstream path: **not** established in this pin (cluster uses node resolv.conf upstream)

See digs.txt for raw probes.
EOF

$KUBECTL delete pod stackdiff-dns-probe --ignore-not-found >/dev/null 2>&1 || true
echo "L1 artifact: $OUT"
