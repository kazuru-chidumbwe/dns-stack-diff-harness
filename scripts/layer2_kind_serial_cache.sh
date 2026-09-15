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
CACHE_TTL="${CACHE_TTL:-20}"
ZONE_TTL="${ZONE_TTL:-20}"   # record TTL; effective staleness = min(cache, record)
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
  # Finalize SHA256SUMS.txt here, as the last write to run.log in this script
  # (log() below and all log() calls above append to it via tee -a; hashing
  # run.log anywhere before cleanup finishes its own logging would be stale).
  if [[ "$rc" == "0" && -f "$OUT/SHA256SUMS.txt.partial" ]]; then
    log "finalizing SHA256SUMS.txt (run.log hashed last, after this line)"
    ( cd "$OUT" && sha256sum ./run.log ) >> "$OUT/SHA256SUMS.txt.partial"
    sort -k2 "$OUT/SHA256SUMS.txt.partial" -o "$OUT/SHA256SUMS.txt"
    rm -f "$OUT/SHA256SUMS.txt.partial"
  fi
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

# Effective TTL is min(cache directive, record TTL); vary the record TTL too.
sed -i "s/^\$TTL 20$/\$TTL $ZONE_TTL/; s/1 60 30 3600 20 )/1 60 30 3600 $ZONE_TTL )/" "$OUT/lab.stackdiff.zone.v1" "$OUT/lab.stackdiff.zone.v2"

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

# Dedicated CoreDNS Service so NodeLocal forwards to CoreDNS, not to itself.
# node-local-dns binds 10.96.0.10; forwarding there is a self-loop, not a hop.
$KUBECTL -n kube-system get svc coredns-direct >/dev/null 2>&1 || $KUBECTL -n kube-system create service clusterip coredns-direct --tcp=53:53 >/dev/null
$KUBECTL -n kube-system patch svc coredns-direct --type=json -p '[{"op":"replace","path":"/spec/selector","value":{"k8s-app":"kube-dns"}},{"op":"replace","path":"/spec/ports","value":[{"name":"dns","port":53,"protocol":"UDP","targetPort":53}]}]' >/dev/null
CD_IP="$($KUBECTL -n kube-system get svc coredns-direct -o jsonpath='{.spec.clusterIP}')"
log "CoreDNS direct service: $CD_IP (NodeLocal upstream; distinct from 10.96.0.10)"

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
    forward . $CD_IP
}
$nl
EOF
$KUBECTL -n kube-system create configmap node-local-dns \
  --from-file=Corefile="$OUT/nodelocal-corefile-new" \
  -o yaml --dry-run=client | $KUBECTL apply -f -
$KUBECTL -n kube-system rollout restart ds/node-local-dns
wait_rollout
sleep 3

log "chain: NodeLocal(169.254.20.10, cache ${CACHE_TTL}s) -> CoreDNS($CD_IP, no cache) -> auth($AUTH_IP, zone v1)"

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

# --- Step 4: poll NodeLocal every ~1s from the moment of promotion until it
# reflects the new value, so propagation lag is a first-observation measurement
# with ~1s resolution, not an upper bound from a single post-hoc sample
# (Reviewer X: the original single sample at CACHE_TTL+8 only proved
# "reconverged by then," not how long reconvergence actually took). ---
POLL_MAX=$(( ( (CACHE_TTL < ZONE_TTL ? CACHE_TTL : ZONE_TTL) * 2 ) + 30 ))
poll_deadline="$(python3 -c "print(float('$t_promote') + $POLL_MAX)")"
recon_epoch=""
recon_answer=""
attempt=0
while true; do
  attempt=$((attempt + 1))
  read -r t_poll a_poll <<<"$(dig_one "poll-nodelocal-$(printf '%02d' "$attempt")" 169.254.20.10)"
  log "POLL #$attempt NodeLocal=$a_poll @${t_poll}"
  if [[ "$a_poll" == "203.0.113.21" ]]; then
    recon_epoch="$t_poll"
    recon_answer="$a_poll"
    break
  fi
  if python3 -c "import sys; sys.exit(0 if float('$t_poll') < float('$poll_deadline') else 1)"; then
    sleep 1
  else
    log "WARN poll window exceeded ${POLL_MAX}s past promote without observing reconvergence"
    break
  fi
done
read -r t_reconv_cd a_reconv_cd <<<"$(dig_one reconverged-coredns 10.96.0.10)"
log "RECONVERGED  NodeLocal=${recon_answer:-NONE} @${recon_epoch:-NA} (poll #$attempt)  CoreDNS=$a_reconv_cd @${t_reconv_cd}"

# --- decision.json: score D(p) at each stage on the single 'answer' axis ---
python3 - "$OUT" "$a_pre_nl" "$a_pre_cd" "$a_post_nl" "$a_post_cd" "${recon_answer:-NONE}" "$a_reconv_cd" \
         "$t_pre_nl" "$t_promote" "$t_post_nl" "${recon_epoch:-NaN}" "$attempt" "$CACHE_TTL" <<'PY'
import json, math, sys
from pathlib import Path

(out, pre_nl, pre_cd, post_nl, post_cd, rec_nl, rec_cd,
 t_pre_nl, t_promote, t_post_nl, t_reconv_nl, poll_attempts, cache_ttl) = sys.argv[1:]

def d(a, b):
    return 0 if a == b else 1

t_pre_nl_f, t_promote_f, cache_ttl_f = float(t_pre_nl), float(t_promote), float(cache_ttl)
lag_measured = None
try:
    t_reconv_nl_f = float(t_reconv_nl)
    if not math.isnan(t_reconv_nl_f):
        lag_measured = t_reconv_nl_f - t_promote_f
except ValueError:
    t_reconv_nl_f = None

# Mechanistic cross-check: the cache entry was populated at t_pre_nl with
# cache_ttl_s TTL, so it expires at t_pre_nl + cache_ttl_s regardless of when
# the change was promoted. Predicted lag is time-from-promote to that expiry
# (0 if the change happened after the entry had already expired).
lag_predicted = max(0.0, (t_pre_nl_f + cache_ttl_f) - t_promote_f)

report = {
    "gate": "layer3-serial-cache-staleness",
    "chain": "NodeLocal(cache) -> CoreDNS(no cache) -> auth",
    "cache_ttl_s": int(cache_ttl_f),
    "pre_change": {"nodelocal": pre_nl, "coredns": pre_cd, "D_answer": d(pre_nl, pre_cd)},
    "post_change_immediate": {"nodelocal": post_nl, "coredns": post_cd, "D_answer": d(post_nl, post_cd)},
    "reconverged": {"nodelocal": rec_nl, "coredns": rec_cd, "D_answer": d(rec_nl, rec_cd)},
    "timestamps_epoch": {
        "pre_nodelocal_query": t_pre_nl_f,
        "change_promoted": t_promote_f,
        "post_change_nodelocal_query": float(t_post_nl),
        "reconverged_nodelocal_query": t_reconv_nl_f,
    },
    "reconverged_after_poll_attempts": int(poll_attempts),
    "propagation_lag_measured_s": lag_measured,
    "propagation_lag_predicted_from_ttl_s": lag_predicted,
    "measurement_note": (
        "propagation_lag_measured_s is a first-observation measurement from ~1s-interval "
        "polling of NodeLocal starting after promotion, resolution ~1 dig round-trip. "
        "propagation_lag_predicted_from_ttl_s is the independent mechanistic prediction "
        "(cache entry populated at pre_nodelocal_query, cache_ttl_s TTL, minus elapsed time "
        "to change_promoted); the two should agree within one poll interval."
    ),
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

DECISION_SHA="$(sha256sum "$OUT/decision.json" | awk '{print $1}')"
log "decision SHA-256 $DECISION_SHA"
log "DONE artifact=$OUT"

# --- SHA256SUMS: hash everything except run.log now. run.log itself is
# hashed and appended inside cleanup(), below, since the EXIT trap always
# fires next and its own log() calls append more lines to run.log — hashing
# it here would produce a checksum the shipped file no longer matches
# (Reviewer X: an earlier pack's script left this half-finished). ---
(
  cd "$OUT"
  find . -type f ! -name 'SHA256SUMS.txt*' ! -name run.log -print0 | sort -z | xargs -0 sha256sum
) > "$OUT/SHA256SUMS.txt.partial"

echo "$OUT"
