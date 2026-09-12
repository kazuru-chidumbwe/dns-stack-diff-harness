#!/usr/bin/env bash
# Kind Layer-2 SERIAL cache-staleness experiment (Reviewer "Gates" major concern
# #1/#9): a genuine consecutive-hop chain, NodeLocal -> CoreDNS -> auth, with
# caching actually enabled on NodeLocal (its real production role), not a bare
# relay. Tests whether a change promoted at the authoritative source is visible
# through the caching hop immediately, or only after its cache entry expires.
#
# This is NOT an adversarial-MITM experiment: no injector, just a real zone
# record change, to isolate the propagation-lag effect cleanly.
#
# Usage on Lab Test Server:
#   ./scripts/layer2_kind_serial_cache.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
KUBECTL="${KUBECTL:-kubectl}"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ROOT/artifacts/layer2-kind-serial-cache-$STAMP"
NS=stackdiff-l2sc
QNAME="www.lab.stackdiff."
CACHE_TTL=20
BACKUP_DIR="$OUT/cm-backup"

mkdir -p "$OUT" "$BACKUP_DIR"

log() { echo "[L2SC $STAMP] $*" | tee -a "$OUT/run.log"; }

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
  $KUBECTL delete ns "$NS" --ignore-not-found --wait=false >/dev/null 2>&1 || true
  exit "$rc"
}
trap cleanup EXIT

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

dig_one() {
  # dig_one <label> <server_ip> -> writes digs/<label>.txt, prints answer IP + epoch
  local label="$1" ip="$2"
  mkdir -p "$OUT/digs"
  local raw
  raw="$(docker exec kosv-control-plane dig @"$ip" "$QNAME" A +time=2 +tries=2 +noall +answer +comments 2>&1)"
  echo "$raw" > "$OUT/digs/${label}.txt"
  local ans
  ans="$(echo "$raw" | awk '/^www\.lab\.stackdiff\./ {print $NF; exit}')"
  local epoch
  epoch="$(date -u +%s.%N)"
  echo "${epoch} ${ans:-NONE}"
}

log "artifact dir $OUT"

$KUBECTL -n kube-system get cm coredns -o jsonpath='{.data.Corefile}' >"$BACKUP_DIR/coredns.Corefile.orig"
$KUBECTL -n kube-system get cm node-local-dns -o jsonpath='{.data.Corefile}' >"$BACKUP_DIR/nodelocal.Corefile.orig"
log "backed up CoreDNS + NodeLocal Corefiles"

$KUBECTL delete ns "$NS" --ignore-not-found --wait=true >/dev/null 2>&1 || true
$KUBECTL create ns "$NS"

# --- auth CoreDNS serving lab.stackdiff from a ConfigMap zone file, v1 (www=.20) ---
cat >"$OUT/lab.stackdiff.zone.v1" <<'EOF'
$ORIGIN lab.stackdiff.
$TTL 20
@       IN SOA ns.lab.stackdiff. hostmaster.lab.stackdiff. (
            1 60 30 3600 20 )
@       IN NS  ns.lab.stackdiff.
ns      IN A   172.30.0.11
agree   IN A   203.0.113.10
www     IN A   203.0.113.20
check   IN A   203.0.113.99
EOF
cat >"$OUT/lab.stackdiff.zone.v2" <<'EOF'
$ORIGIN lab.stackdiff.
$TTL 20
@       IN SOA ns.lab.stackdiff. hostmaster.lab.stackdiff. (
            2 60 30 3600 20 )
@       IN NS  ns.lab.stackdiff.
ns      IN A   172.30.0.11
agree   IN A   203.0.113.10
www     IN A   203.0.113.21
check   IN A   203.0.113.99
EOF

cat >"$OUT/auth-corefile" <<EOF
lab.stackdiff.:53 {
    errors
    log
    file /zones/lab.stackdiff.zone
}
EOF

$KUBECTL -n "$NS" create configmap stackdiff-auth-config \
  --from-file=Corefile="$OUT/auth-corefile" \
  --from-file=lab.stackdiff.zone="$OUT/lab.stackdiff.zone.v1"

if ! docker exec kosv-control-plane ctr -n k8s.io images ls | grep -q coredns; then
  docker save registry.k8s.io/coredns/coredns:v1.11.3 | docker exec -i kosv-control-plane ctr -n k8s.io images import - || true
fi

cat >"$OUT/auth-deploy.yaml" <<EOF
apiVersion: apps/v1
kind: Deployment
metadata:
  name: stackdiff-auth
  namespace: $NS
spec:
  replicas: 1
  selector:
    matchLabels: {app: stackdiff-auth}
  template:
    metadata:
      labels: {app: stackdiff-auth}
    spec:
      containers:
      - name: coredns
        image: registry.k8s.io/coredns/coredns:v1.11.3
        imagePullPolicy: IfNotPresent
        args: ["-conf", "/config/Corefile"]
        ports:
        - {containerPort: 53, name: dns-udp, protocol: UDP}
        - {containerPort: 53, name: dns-tcp, protocol: TCP}
        volumeMounts:
        - {name: config, mountPath: /config}
        - {name: zones, mountPath: /zones}
      volumes:
      - name: config
        configMap: {name: stackdiff-auth-config, items: [{key: Corefile, path: Corefile}]}
      - name: zones
        configMap: {name: stackdiff-auth-config, items: [{key: lab.stackdiff.zone, path: lab.stackdiff.zone}]}
---
apiVersion: v1
kind: Service
metadata:
  name: stackdiff-auth
  namespace: $NS
spec:
  selector: {app: stackdiff-auth}
  ports:
  - {name: dns-udp, port: 53, protocol: UDP, targetPort: 53}
  - {name: dns-tcp, port: 53, protocol: TCP, targetPort: 53}
EOF
$KUBECTL apply -f "$OUT/auth-deploy.yaml"
$KUBECTL -n "$NS" rollout status deploy/stackdiff-auth --timeout=180s
AUTH_IP="$($KUBECTL -n "$NS" get svc stackdiff-auth -o jsonpath='{.spec.clusterIP}')"
log "auth ClusterIP=$AUTH_IP (v1 zone: www=203.0.113.20)"

# --- CoreDNS: lab.stackdiff -> auth directly, NO cache (always fresh) ---
corefile="$($KUBECTL -n kube-system get cm coredns -o jsonpath='{.data.Corefile}')"
cat >"$OUT/coredns-corefile-new" <<EOF
lab.stackdiff:53 {
    errors
    log
    forward . $AUTH_IP
}
$corefile
EOF
$KUBECTL -n kube-system create configmap coredns \
  --from-file=Corefile="$OUT/coredns-corefile-new" \
  -o yaml --dry-run=client | $KUBECTL apply -f -
$KUBECTL -n kube-system rollout restart deploy/coredns
$KUBECTL -n kube-system rollout status deploy/coredns --timeout=180s

# --- NodeLocal: lab.stackdiff -> CoreDNS, WITH cache (its real production role) ---
nl="$($KUBECTL -n kube-system get cm node-local-dns -o jsonpath='{.data.Corefile}')"
cat >"$OUT/nodelocal-corefile-new" <<EOF
lab.stackdiff:53 {
    errors
    cache $CACHE_TTL {
        success 100 $CACHE_TTL
    }
    reload
    loop
    bind 169.254.20.10 10.96.0.10
    forward . 10.96.0.10
}
$nl
EOF
$KUBECTL -n kube-system create configmap node-local-dns \
  --from-file=Corefile="$OUT/nodelocal-corefile-new" \
  -o yaml --dry-run=client | $KUBECTL apply -f -
$KUBECTL -n kube-system rollout restart ds/node-local-dns
wait_rollout
sleep 3

log "chain: NodeLocal(169.254.20.10, cache ${CACHE_TTL}s) -> CoreDNS(10.96.0.10, no cache) -> auth($AUTH_IP, zone v1)"

# --- Step 1: pre-change pin (populates NodeLocal's cache with v1 answer) ---
read -r t_pre_nl a_pre_nl <<<"$(dig_one pre-nodelocal 169.254.20.10)"
read -r t_pre_cd a_pre_cd <<<"$(dig_one pre-coredns 10.96.0.10)"
log "PRE  NodeLocal=$a_pre_nl @${t_pre_nl}  CoreDNS=$a_pre_cd @${t_pre_cd}"

# --- Step 2: "promote a change" — update the authoritative zone, restart auth ---
$KUBECTL -n "$NS" create configmap stackdiff-auth-config \
  --from-file=Corefile="$OUT/auth-corefile" \
  --from-file=lab.stackdiff.zone="$OUT/lab.stackdiff.zone.v2" \
  -o yaml --dry-run=client | $KUBECTL apply -f -
$KUBECTL -n "$NS" rollout restart deploy/stackdiff-auth
$KUBECTL -n "$NS" rollout status deploy/stackdiff-auth --timeout=180s
t_promote="$(date -u +%s.%N)"
log "PROMOTED change at auth: www 203.0.113.20 -> 203.0.113.21 (t=${t_promote})"

# --- Step 3: immediately re-query both (within NodeLocal's cache TTL window) ---
read -r t_post_cd a_post_cd <<<"$(dig_one post-change-coredns 10.96.0.10)"
read -r t_post_nl a_post_nl <<<"$(dig_one post-change-nodelocal 169.254.20.10)"
log "POST-CHANGE (immediate)  CoreDNS=$a_post_cd @${t_post_cd}  NodeLocal=$a_post_nl @${t_post_nl}"

# --- Step 4: wait past the cache TTL, then re-query NodeLocal ---
sleep_for=$((CACHE_TTL + 8))
log "sleeping ${sleep_for}s past NodeLocal's ${CACHE_TTL}s cache TTL"
sleep "$sleep_for"
read -r t_reconv_nl a_reconv_nl <<<"$(dig_one reconverged-nodelocal 169.254.20.10)"
read -r t_reconv_cd a_reconv_cd <<<"$(dig_one reconverged-coredns 10.96.0.10)"
log "RECONVERGED  NodeLocal=$a_reconv_nl @${t_reconv_nl}  CoreDNS=$a_reconv_cd @${t_reconv_cd}"

# --- decision.json: score D(p) at each stage on the single 'answer' axis ---
python3 - "$OUT" "$a_pre_nl" "$a_pre_cd" "$a_post_nl" "$a_post_cd" "$a_reconv_nl" "$a_reconv_cd" \
         "$t_pre_nl" "$t_promote" "$t_post_nl" "$t_reconv_nl" "$CACHE_TTL" <<'PY'
import json, sys
from pathlib import Path

(out, pre_nl, pre_cd, post_nl, post_cd, rec_nl, rec_cd,
 t_pre_nl, t_promote, t_post_nl, t_reconv_nl, cache_ttl) = sys.argv[1:]

def d(a, b):
    return 0 if a == b else 1

report = {
    "gate": "layer3-serial-cache-staleness",
    "chain": "NodeLocal(cache) -> CoreDNS(no cache) -> auth",
    "cache_ttl_s": int(cache_ttl),
    "pre_change": {"nodelocal": pre_nl, "coredns": pre_cd, "D_answer": d(pre_nl, pre_cd)},
    "post_change_immediate": {"nodelocal": post_nl, "coredns": post_cd, "D_answer": d(post_nl, post_cd)},
    "reconverged": {"nodelocal": rec_nl, "coredns": rec_cd, "D_answer": d(rec_nl, rec_cd)},
    "timestamps_epoch": {
        "pre_nodelocal_query": float(t_pre_nl),
        "change_promoted": float(t_promote),
        "post_change_nodelocal_query": float(t_post_nl),
        "reconverged_nodelocal_query": float(t_reconv_nl),
    },
    "propagation_lag_observed_s": float(t_reconv_nl) - float(t_promote),
    "finding": (
        "NodeLocal served a stale cached answer immediately after the authoritative "
        "change was promoted, while CoreDNS (uncached) reflected the change "
        "instantly; NodeLocal reconverged only after its cache TTL elapsed."
        if d(post_nl, post_cd) == 1 and d(rec_nl, rec_cd) == 0
        else "Unexpected outcome — see raw digs for manual inspection."
    ),
}
raw = json.dumps(report, indent=2, sort_keys=True) + "\n"
Path(out, "decision.json").write_text(raw, encoding="utf-8")
print(raw)
PY

# --- SHA256SUMS ---
(
  cd "$OUT"
  find . -type f ! -name 'SHA256SUMS.txt*' ! -name run.log -print0 | sort -z | xargs -0 sha256sum
) > "$OUT/SHA256SUMS.txt.partial"
DECISION_SHA="$(sha256sum "$OUT/decision.json" | awk '{print $1}')"
log "decision SHA-256 $DECISION_SHA"

log "DONE artifact=$OUT"
echo "$OUT"
