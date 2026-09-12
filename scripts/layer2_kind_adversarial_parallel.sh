#!/usr/bin/env bash
# Kind Layer-2 (PARALLEL topology fix): NodeLocal and CoreDNS each forward
# lab.stackdiff DIRECTLY to the MITM, independently, matching the pair-mode
# design invariant (Section III-D) instead of the prior serial chain
# (NodeLocal -> CoreDNS -> MITM). See docs/ARCHITECTURE.md.
#
# Usage on Lab Test Server:
#   KUBECTL='docker exec kosv-control-plane kubectl' ./scripts/layer2_kind_adversarial_parallel.sh
#
# Restores CoreDNS + NodeLocal ConfigMaps on exit (SUCCESS or FAIL).
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KUBECTL="${KUBECTL:-kubectl}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ROOT/artifacts/layer2-kind-parallel-$STAMP"
NS=stackdiff-l2p
MITM_MODES=(passthrough additional-glue malformed-truncate)
QNAME="www.lab.stackdiff."
BACKUP_DIR="$OUT/cm-backup"

mkdir -p "$OUT" "$BACKUP_DIR" "$OUT/modes"

log() { echo "[L2P $STAMP] $*" | tee -a "$OUT/run.log"; }

cleanup() {
  local rc=$?
  log "cleanup rc=$rc — restoring ConfigMaps if backed up"
  if [[ -f "$BACKUP_DIR/coredns.Corefile.orig" ]]; then
    $KUBECTL -n kube-system create configmap coredns \
      --from-file=Corefile="$BACKUP_DIR/coredns.Corefile.orig" \
      -o yaml --dry-run=client | $KUBECTL apply -f - || true
    $KUBECTL -n kube-system rollout restart deploy/coredns >/dev/null 2>&1 || true
  fi
  if [[ -f "$BACKUP_DIR/nodelocal.Corefile.orig" ]]; then
    $KUBECTL -n kube-system create configmap node-local-dns \
      --from-file=Corefile="$BACKUP_DIR/nodelocal.Corefile.orig" \
      -o yaml --dry-run=client | $KUBECTL apply -f - || true
    $KUBECTL -n kube-system rollout restart ds/node-local-dns >/dev/null 2>&1 || true
  fi
  $KUBECTL -n kube-system rollout status deploy/coredns --timeout=120s >/dev/null 2>&1 || true
  exit "$rc"
}
trap cleanup EXIT

ensure_dig_on_node() {
  if docker exec kosv-control-plane sh -c 'command -v dig' >/dev/null 2>&1; then
    return 0
  fi
  log "installing dnsutils inside kosv-control-plane"
  docker exec kosv-control-plane bash -lc 'export DEBIAN_FRONTEND=noninteractive; apt-get update -qq && apt-get install -y -qq dnsutils >/dev/null'
}

dig_both() {
  local mode="$1" tag="$2"
  local dir="$OUT/modes/$mode"
  mkdir -p "$dir"
  {
    echo "=== mode=$mode tag=$tag q=$QNAME ==="
    echo "--- NodeLocal 169.254.20.10 ---"
    docker exec kosv-control-plane dig @"169.254.20.10" "$QNAME" A +time=3 +tries=2 +noall +answer +authority +additional +comments 2>&1 || true
    echo "--- CoreDNS 10.96.0.10 ---"
    docker exec kosv-control-plane dig @"10.96.0.10" "$QNAME" A +time=3 +tries=2 +noall +answer +authority +additional +comments 2>&1 || true
    echo "--- NodeLocal example.com (control; should use node upstream, not MITM) ---"
    docker exec kosv-control-plane dig @"169.254.20.10" example.com A +time=3 +tries=1 +noall +answer +comments 2>&1 || true
  } | tee "$dir/digs-$tag.txt"
}

wait_rollout() {
  $KUBECTL -n kube-system rollout status deploy/coredns --timeout=180s
  for i in $(seq 1 36); do
    ready="$($KUBECTL -n kube-system get ds node-local-dns -o jsonpath='{.status.numberReady}' 2>/dev/null || echo 0)"
    desired="$($KUBECTL -n kube-system get ds node-local-dns -o jsonpath='{.status.desiredNumberScheduled}' 2>/dev/null || echo 1)"
    [[ "$ready" == "$desired" && "$ready" != "0" ]] && return 0
    sleep 5
  done
  log "WARN: node-local-dns not fully ready"
}

log "artifact dir $OUT"
ensure_dig_on_node

$KUBECTL -n kube-system get cm coredns -o jsonpath='{.data.Corefile}' >"$BACKUP_DIR/coredns.Corefile.orig"
$KUBECTL -n kube-system get cm node-local-dns -o jsonpath='{.data.Corefile}' >"$BACKUP_DIR/nodelocal.Corefile.orig"
log "backed up CoreDNS + NodeLocal Corefiles"

$KUBECTL delete ns "$NS" --ignore-not-found --wait=true >/dev/null 2>&1 || true
$KUBECTL create ns "$NS"

cat >"$OUT/auth-corefile" <<'EOF'
lab.stackdiff.:53 {
    errors
    log
    file /zones/lab.stackdiff.zone
}
EOF
cp "$ROOT/deploy/coredns/zones/lab.stackdiff.zone" "$OUT/lab.stackdiff.zone"

$KUBECTL -n "$NS" create configmap stackdiff-auth-config \
  --from-file=Corefile="$OUT/auth-corefile" \
  --from-file=lab.stackdiff.zone="$OUT/lab.stackdiff.zone"

$KUBECTL -n "$NS" create configmap stackdiff-mitm-code \
  --from-file=dns_mitm.py="$ROOT/deploy/mitm/dns_mitm.py"

log "importing images into kosv-control-plane containerd (if missing)"
for img in python:3.12-slim registry.k8s.io/coredns/coredns:v1.11.3; do
  if ! docker exec kosv-control-plane ctr -n k8s.io images ls | grep -q "${img##*/}"; then
    docker save "$img" | docker exec -i kosv-control-plane ctr -n k8s.io images import - || true
  fi
done

cat >"$OUT/auth-deploy.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: stackdiff-auth
  namespace: $NS
  labels:
    app: stackdiff-auth
spec:
  replicas: 1
  selector:
    matchLabels:
      app: stackdiff-auth
  template:
    metadata:
      labels:
        app: stackdiff-auth
    spec:
      containers:
      - name: coredns
        image: registry.k8s.io/coredns/coredns:v1.11.3
        imagePullPolicy: IfNotPresent
        args: ["-conf", "/config/Corefile"]
        ports:
        - containerPort: 53
          name: dns-udp
          protocol: UDP
        - containerPort: 53
          name: dns-tcp
          protocol: TCP
        volumeMounts:
        - name: config
          mountPath: /config
        - name: zones
          mountPath: /zones
      volumes:
      - name: config
        configMap:
          name: stackdiff-auth-config
          items:
          - key: Corefile
            path: Corefile
      - name: zones
        configMap:
          name: stackdiff-auth-config
          items:
          - key: lab.stackdiff.zone
            path: lab.stackdiff.zone
---
apiVersion: v1
kind: Service
metadata:
  name: stackdiff-auth
  namespace: $NS
spec:
  selector:
    app: stackdiff-auth
  ports:
  - name: dns-udp
    port: 53
    protocol: UDP
    targetPort: 53
  - name: dns-tcp
    port: 53
    protocol: TCP
    targetPort: 53
EOF
$KUBECTL apply -f "$OUT/auth-deploy.yaml"
$KUBECTL -n "$NS" rollout status deploy/stackdiff-auth --timeout=180s
AUTH_IP="$($KUBECTL -n "$NS" get svc stackdiff-auth -o jsonpath='{.spec.clusterIP}')"
log "auth ClusterIP=$AUTH_IP"

deploy_mitm() {
  local mode="$1"
  $KUBECTL -n "$NS" delete deploy stackdiff-mitm --ignore-not-found --wait=true >/dev/null 2>&1 || true
  $KUBECTL -n "$NS" delete pod -l app=stackdiff-mitm --ignore-not-found --wait=true >/dev/null 2>&1 || true
  sleep 2
  cat >"$OUT/mitm-deploy.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: stackdiff-mitm
  namespace: $NS
  labels:
    app: stackdiff-mitm
spec:
  replicas: 1
  strategy:
    type: Recreate
  selector:
    matchLabels:
      app: stackdiff-mitm
  template:
    metadata:
      labels:
        app: stackdiff-mitm
        stackdiff-mode: "$mode"
      annotations:
        stackdiff.mode: "$mode"
    spec:
      containers:
      - name: mitm
        image: python:3.12-slim
        imagePullPolicy: IfNotPresent
        command: ["python3", "/app/dns_mitm.py"]
        args:
          - "--listen"
          - "0.0.0.0"
          - "--port"
          - "53"
          - "--upstream"
          - "$AUTH_IP"
          - "--upstream-port"
          - "53"
          - "--mode"
          - "$mode"
        ports:
        - containerPort: 53
          protocol: UDP
        - containerPort: 53
          protocol: TCP
        securityContext:
          runAsUser: 0
          capabilities:
            add: ["NET_BIND_SERVICE"]
        volumeMounts:
        - name: code
          mountPath: /app
      volumes:
      - name: code
        configMap:
          name: stackdiff-mitm-code
          defaultMode: 0755
---
apiVersion: v1
kind: Service
metadata:
  name: stackdiff-mitm
  namespace: $NS
spec:
  selector:
    app: stackdiff-mitm
  ports:
  - name: dns-udp
    port: 53
    protocol: UDP
    targetPort: 53
  - name: dns-tcp
    port: 53
    protocol: TCP
    targetPort: 53
EOF
  $KUBECTL apply -f "$OUT/mitm-deploy.yaml"
  $KUBECTL -n "$NS" rollout status deploy/stackdiff-mitm --timeout=180s
  MITM_IP="$($KUBECTL -n "$NS" get svc stackdiff-mitm -o jsonpath='{.spec.clusterIP}')"
  log "mitm mode=$mode ClusterIP=$MITM_IP"
  mkdir -p "$OUT/modes/$mode"
  echo "$MITM_IP" >"$OUT/modes/$mode/mitm-ip.txt"
  sleep 2
  POD="$($KUBECTL -n "$NS" get pod -l "app=stackdiff-mitm,stackdiff-mode=$mode" --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')"
  if [[ -z "$POD" ]]; then
    POD="$($KUBECTL -n "$NS" get pod -l app=stackdiff-mitm --field-selector=status.phase=Running -o jsonpath='{.items[0].metadata.name}')"
  fi
  ARGS="$($KUBECTL -n "$NS" get pod "$POD" -o jsonpath='{.spec.containers[0].args}')"
  echo "pod=$POD args=$ARGS" | tee "$OUT/modes/$mode/mitm-pod-args.txt"
  $KUBECTL -n "$NS" logs "$POD" --tail=50 | tee "$OUT/modes/$mode/mitm-boot.txt" || true
  if ! grep -q -- "$mode" "$OUT/modes/$mode/mitm-pod-args.txt"; then
    log "ERROR: mitm pod args missing mode=$mode ($ARGS)"
    return 1
  fi
}

patch_coredns_to_mitm() {
  local mitm_ip="$1"
  local corefile
  corefile="$($KUBECTL -n kube-system get cm coredns -o jsonpath='{.data.Corefile}')"
  corefile="$(printf '%s\n' "$corefile" | awk '
    BEGIN{skip=0}
    /^lab\.stackdiff/ {skip=1}
    skip && /^}/ {skip=0; next}
    !skip {print}
  ')"
  cat >"$OUT/coredns-corefile-new" <<EOF
lab.stackdiff:53 {
    errors
    log
    forward . $mitm_ip {
        max_concurrent 1000
    }
}
$corefile
EOF
  $KUBECTL -n kube-system create configmap coredns \
    --from-file=Corefile="$OUT/coredns-corefile-new" \
    -o yaml --dry-run=client | $KUBECTL apply -f -
  $KUBECTL -n kube-system rollout restart deploy/coredns
  $KUBECTL -n kube-system rollout status deploy/coredns --timeout=180s
}

# PARALLEL FIX: NodeLocal forwards lab.stackdiff DIRECTLY to the MITM (same
# target as CoreDNS), not to CoreDNS. Both hops now query the MITM
# independently, restoring the Section III-D pair-mode invariant.
patch_nodelocal_to_mitm() {
  local mitm_ip="$1"
  local nl
  nl="$($KUBECTL -n kube-system get cm node-local-dns -o jsonpath='{.data.Corefile}')"
  nl="$(printf '%s\n' "$nl" | awk '
    BEGIN{skip=0}
    /^lab\.stackdiff/ {skip=1}
    skip && /^}/ {skip=0; next}
    !skip {print}
  ')"
  cat >"$OUT/nodelocal-corefile-new" <<EOF
lab.stackdiff:53 {
    errors
    reload
    loop
    bind 169.254.20.10 10.96.0.10
    forward . $mitm_ip
}
$nl
EOF
  $KUBECTL -n kube-system create configmap node-local-dns \
    --from-file=Corefile="$OUT/nodelocal-corefile-new" \
    -o yaml --dry-run=client | $KUBECTL apply -f -
  $KUBECTL -n kube-system rollout restart ds/node-local-dns
  wait_rollout
}

mkdir -p "$OUT/modes/passthrough"
deploy_mitm passthrough
MITM_IP="$($KUBECTL -n "$NS" get svc stackdiff-mitm -o jsonpath='{.spec.clusterIP}')"
patch_coredns_to_mitm "$MITM_IP"
patch_nodelocal_to_mitm "$MITM_IP"
sleep 5
dig_both passthrough baseline

for mode in additional-glue malformed-truncate; do
  mkdir -p "$OUT/modes/$mode"
  deploy_mitm "$mode"
  NEW_IP="$($KUBECTL -n "$NS" get svc stackdiff-mitm -o jsonpath='{.spec.clusterIP}')"
  if [[ "$NEW_IP" != "$MITM_IP" ]]; then
    MITM_IP="$NEW_IP"
    patch_coredns_to_mitm "$MITM_IP"
    patch_nodelocal_to_mitm "$MITM_IP"
  fi
  $KUBECTL -n kube-system rollout restart deploy/coredns
  $KUBECTL -n kube-system rollout status deploy/coredns --timeout=180s
  $KUBECTL -n kube-system rollout restart ds/node-local-dns
  wait_rollout
  sleep 3
  dig_both "$mode" pin
done

{
  echo "host=$(hostname)"
  echo "stamp=$STAMP"
  uname -a
  docker --version
  $KUBECTL get nodes -o wide
  $KUBECTL -n kube-system get ds/node-local-dns -o wide
  $KUBECTL -n kube-system get deploy/coredns -o wide
  $KUBECTL -n kube-system get svc -o wide
  $KUBECTL -n "$NS" get all -o wide
} | tee "$OUT/env.txt"

(
  cd "$OUT"
  find . -type f ! -name SHA256SUMS.txt -print0 | sort -z | xargs -0 sha256sum
) | tee "$OUT/SHA256SUMS.txt"

cat >"$OUT/SUMMARY.md" <<EOF
# Layer-2 Kind adversarial consecutive-hop pins, PARALLEL topology ($STAMP)

- Host: Lab Test Server \`$(hostname)\`
- Cluster: Kind \`kosv\` / \`kosv-control-plane\`
- Hops: NodeLocal DNSCache \`169.254.20.10\` and CoreDNS kube-dns \`10.96.0.10\` **each forward \`lab.stackdiff\` directly to the MITM independently** (parallel pair-mode topology — fixes the serial NodeLocal->CoreDNS->MITM chain in \`layer2-kind-20260912T004414Z\`; see \`docs/ARCHITECTURE.md\`).
- Query: \`$QNAME\` A
- Modes: passthrough · additional-glue · malformed-truncate
- DNSSEC: matched non-validating
- Isolation: Kind CNI / hostNetwork NodeLocal; application-layer MITM in-cluster
- Control: \`example.com\` via NodeLocal should **not** traverse MITM (node upstream)
- Claim fence: laboratory Kind path under pinned zone; **not** production Kubernetes; **not** OS-layer channels

## Digests

- Artifact tree SHA index: see \`SHA256SUMS.txt\` — verify with \`sha256sum -c SHA256SUMS.txt\`
- Load-bearing dig transcripts: \`modes/additional-glue/digs-pin.txt\` and \`modes/malformed-truncate/digs-pin.txt\` (per-file SHAs in \`SHA256SUMS.txt\`)

## How to read

Compare NodeLocal vs CoreDNS answers/ADDITIONAL/RCODE/FailureMode under each mode.
Passthrough is the agreeing control. additional-glue / malformed-truncate are load-bearing L2 pins.
Unlike the prior serial pack, agreement here is a genuine independent-hop result: both
NodeLocal and CoreDNS query the MITM on their own, comparable to the August pair-mode pins.
EOF

log "DONE artifact=$OUT"
echo "$OUT"
