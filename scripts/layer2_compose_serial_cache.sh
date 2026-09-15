#!/usr/bin/env bash
# Compose SERIAL cache-staleness experiment: Unbound (cache) -> CoreDNS-forwarder
# (no cache) -> auth. Independent second pairing of the Kind NodeLocal chain in
# scripts/layer2_kind_serial_cache.sh. Same measurement: promote an authoritative
# A-record change, poll the caching role until the new answer appears, compare
# the first-observation lag to remaining TTL.
#
# Usage:
#   CACHE_TTL=20 ZONE_TTL=20 ./scripts/layer2_compose_serial_cache.sh
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="$ROOT/artifacts/layer2-compose-serial-cache-$STAMP"
QNAME="www.lab.stackdiff."
CACHE_TTL="${CACHE_TTL:-20}"
ZONE_TTL="${ZONE_TTL:-20}"
EFF_TTL=$(( CACHE_TTL < ZONE_TTL ? CACHE_TTL : ZONE_TTL ))
PROJECT="stackdiffserial"
UNBOUND_IMAGE="${UNBOUND_IMAGE:-mvance/unbound:1.20.0}"
COREDNS_IMAGE="${COREDNS_IMAGE:-coredns/coredns:1.11.3}"
UNBOUND_PORT="${UNBOUND_PORT:-9153}"
COREDNS_PORT="${COREDNS_PORT:-9154}"
AUTH_IP="172.31.0.10"
FWD_IP="172.31.0.30"
UNBOUND_IP="172.31.0.20"

mkdir -p "$OUT/zones" "$OUT/digs"

log() { echo "[L2CSC $STAMP] $*" | tee -a "$OUT/run.log"; }

compose() {
  docker compose -p "$PROJECT" -f "$OUT/compose.yaml" "$@"
}

cleanup() {
  local rc=$?
  log "cleanup rc=$rc — bringing down compose project $PROJECT"
  compose down --remove-orphans >/dev/null 2>&1 || true
  if [[ "$rc" == "0" && -f "$OUT/SHA256SUMS.txt.partial" ]]; then
    log "finalizing SHA256SUMS.txt (run.log hashed last, after this line)"
    ( cd "$OUT" && sha256sum ./run.log ) >> "$OUT/SHA256SUMS.txt.partial"
    sort -k2 "$OUT/SHA256SUMS.txt.partial" -o "$OUT/SHA256SUMS.txt"
    rm -f "$OUT/SHA256SUMS.txt.partial"
  fi
  exit "$rc"
}
trap cleanup EXIT

dig_one() {
  local label="$1" ip="$2" port="$3"
  local raw
  raw="$(dig @"$ip" -p "$port" "$QNAME" A +time=2 +tries=2 +noall +answer +comments 2>&1 || true)"
  echo "$raw" > "$OUT/digs/${label}.txt"
  local ans
  ans="$(echo "$raw" | awk '/^www\.lab\.stackdiff\./ {print $NF; exit}')"
  local epoch
  epoch="$(date -u +%s.%N)"
  echo "${epoch} ${ans:-NONE}"
}

wait_answers() {
  local ip="$1" port="$2" expect="$3" tries="${4:-30}"
  local i t a
  for i in $(seq 1 "$tries"); do
    read -r t a <<<"$(dig_one "wait-${port}-${i}" "$ip" "$port")"
    if [[ "$a" == "$expect" ]]; then
      return 0
    fi
    sleep 1
  done
  log "WARN: $ip:$port did not return $expect after ${tries}s (last=$a)"
  return 1
}

log "artifact dir $OUT ttl cache=$CACHE_TTL zone=$ZONE_TTL effective=$EFF_TTL image=$UNBOUND_IMAGE"

cat >"$OUT/zones/lab.stackdiff.zone" <<EOF
\$ORIGIN lab.stackdiff.
\$TTL $ZONE_TTL
@       IN SOA ns.lab.stackdiff. hostmaster.lab.stackdiff. (
            1 60 30 3600 $ZONE_TTL )
@       IN NS  ns.lab.stackdiff.
ns      IN A   ${AUTH_IP}
agree   IN A   203.0.113.10
www     IN A   203.0.113.20
check   IN A   203.0.113.99
EOF
cp "$OUT/zones/lab.stackdiff.zone" "$OUT/lab.stackdiff.zone.v1"
cat >"$OUT/lab.stackdiff.zone.v2" <<EOF
\$ORIGIN lab.stackdiff.
\$TTL $ZONE_TTL
@       IN SOA ns.lab.stackdiff. hostmaster.lab.stackdiff. (
            2 60 30 3600 $ZONE_TTL )
@       IN NS  ns.lab.stackdiff.
ns      IN A   ${AUTH_IP}
agree   IN A   203.0.113.10
www     IN A   203.0.113.21
check   IN A   203.0.113.99
EOF

cat >"$OUT/auth-corefile" <<EOF
lab.stackdiff. {
    file /zones/lab.stackdiff.zone
    log
    errors
}
EOF

cat >"$OUT/coredns-fwd-corefile" <<EOF
. {
    forward . ${AUTH_IP}
    errors
    log
}
EOF

cat >"$OUT/unbound.conf" <<EOF
server:
    verbosity: 1
    interface: 0.0.0.0
    port: 53
    do-ip4: yes
    do-ip6: no
    do-udp: yes
    do-tcp: yes
    access-control: 0.0.0.0/0 allow
    username: ""
    directory: "/opt/unbound/etc/unbound"
    pidfile: "/opt/unbound/etc/unbound/unbound.pid"
    domain-insecure: "lab.stackdiff."
    cache-min-ttl: 0
    cache-max-ttl: ${EFF_TTL}
    prefetch: no
    prefetch-key: no
    serve-expired: no
    qname-minimisation: no
    module-config: "iterator"
    val-permissive-mode: yes

forward-zone:
    name: "."
    forward-addr: ${FWD_IP}
EOF

cat >"$OUT/compose.yaml" <<EOF
services:
  auth:
    image: ${COREDNS_IMAGE}
    command: ["-conf", "/Corefile"]
    volumes:
      - ${OUT}/auth-corefile:/Corefile:ro
      - ${OUT}/zones:/zones
    networks:
      serialnet:
        ipv4_address: ${AUTH_IP}
  coredns_fwd:
    image: ${COREDNS_IMAGE}
    command: ["-conf", "/Corefile"]
    volumes:
      - ${OUT}/coredns-fwd-corefile:/Corefile:ro
    depends_on: [auth]
    ports:
      - "127.0.0.1:${COREDNS_PORT}:53/udp"
      - "127.0.0.1:${COREDNS_PORT}:53/tcp"
    networks:
      serialnet:
        ipv4_address: ${FWD_IP}
  unbound:
    image: ${UNBOUND_IMAGE}
    volumes:
      - ${OUT}/unbound.conf:/opt/unbound/etc/unbound/unbound.conf:ro
    depends_on: [coredns_fwd]
    ports:
      - "127.0.0.1:${UNBOUND_PORT}:53/udp"
      - "127.0.0.1:${UNBOUND_PORT}:53/tcp"
    healthcheck:
      disable: true
    networks:
      serialnet:
        ipv4_address: ${UNBOUND_IP}
networks:
  serialnet:
    driver: bridge
    ipam:
      config:
        - subnet: 172.31.0.0/24
EOF

compose down --remove-orphans >/dev/null 2>&1 || true
compose up -d --wait --wait-timeout 60 || compose up -d
sleep 2
wait_answers 127.0.0.1 "$COREDNS_PORT" "203.0.113.20" 40
wait_answers 127.0.0.1 "$UNBOUND_PORT" "203.0.113.20" 40
log "chain: Unbound(127.0.0.1:${UNBOUND_PORT}, cache-max-ttl ${ZONE_TTL}s) -> CoreDNS-fwd(127.0.0.1:${COREDNS_PORT}, no cache) -> auth(${AUTH_IP}, zone v1)"

read -r t_pre_ub a_pre_ub <<<"$(dig_one pre-unbound 127.0.0.1 "$UNBOUND_PORT")"
read -r t_pre_cd a_pre_cd <<<"$(dig_one pre-coredns 127.0.0.1 "$COREDNS_PORT")"
log "PRE  Unbound=$a_pre_ub @${t_pre_ub}  CoreDNS-fwd=$a_pre_cd @${t_pre_cd}"

cp "$OUT/lab.stackdiff.zone.v2" "$OUT/zones/lab.stackdiff.zone"
compose restart -t 2 auth >/dev/null
sleep 1
wait_answers 127.0.0.1 "$COREDNS_PORT" "203.0.113.21" 40
t_promote="$(date -u +%s.%N)"
log "PROMOTED change at auth: www 203.0.113.20 -> 203.0.113.21 (t=${t_promote})"

read -r t_post_cd a_post_cd <<<"$(dig_one post-change-coredns 127.0.0.1 "$COREDNS_PORT")"
read -r t_post_ub a_post_ub <<<"$(dig_one post-change-unbound 127.0.0.1 "$UNBOUND_PORT")"
log "POST-CHANGE (immediate)  CoreDNS-fwd=$a_post_cd @${t_post_cd}  Unbound=$a_post_ub @${t_post_ub}"

POLL_MAX=$(( EFF_TTL * 2 + 30 ))
poll_deadline="$(python3 -c "print(float('$t_promote') + $POLL_MAX)")"
recon_epoch=""
recon_answer=""
attempt=0
while true; do
  attempt=$((attempt + 1))
  read -r t_poll a_poll <<<"$(dig_one "$(printf 'poll-unbound-%03d' "$attempt")" 127.0.0.1 "$UNBOUND_PORT")"
  log "POLL #$attempt Unbound=$a_poll @${t_poll}"
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
read -r t_reconv_cd a_reconv_cd <<<"$(dig_one reconverged-coredns 127.0.0.1 "$COREDNS_PORT")"
log "RECONVERGED  Unbound=${recon_answer:-NONE} @${recon_epoch:-NA} (poll #$attempt)  CoreDNS-fwd=$a_reconv_cd @${t_reconv_cd}"

python3 - "$OUT" "$a_pre_ub" "$a_pre_cd" "$a_post_ub" "$a_post_cd" "${recon_answer:-NONE}" "$a_reconv_cd" \
         "$t_pre_ub" "$t_promote" "$t_post_ub" "${recon_epoch:-NaN}" "$attempt" "$EFF_TTL" "$UNBOUND_IMAGE" <<'PY'
import json, math, sys
from pathlib import Path

(out, pre_ub, pre_cd, post_ub, post_cd, rec_ub, rec_cd,
 t_pre_ub, t_promote, t_post_ub, t_reconv_ub, poll_attempts, cache_ttl, image) = sys.argv[1:]

def d(a, b):
    return 0 if a == b else 1

t_pre_f, t_promote_f, cache_ttl_f = float(t_pre_ub), float(t_promote), float(cache_ttl)
lag_measured = None
try:
    t_reconv_f = float(t_reconv_ub)
    if not math.isnan(t_reconv_f):
        lag_measured = t_reconv_f - t_promote_f
except ValueError:
    t_reconv_f = None

lag_predicted = max(0.0, (t_pre_f + cache_ttl_f) - t_promote_f)
reconverged_ok = rec_ub == "203.0.113.21" and rec_cd == "203.0.113.21"
stale_ok = post_ub == "203.0.113.20" and post_cd == "203.0.113.21"
if stale_ok and reconverged_ok:
    finding = (
        "Unbound served a stale cached answer immediately after the authoritative "
        "change was promoted, while CoreDNS-forwarder (uncached) reflected the change "
        "instantly; Unbound reconverged only after its cache TTL elapsed."
    )
    status = "PASS"
elif not reconverged_ok:
    finding = "No reconvergence observed within the poll window — finding not earned."
    status = "FAIL"
else:
    finding = "Unexpected outcome — see raw digs for manual inspection."
    status = "FAIL"

report = {
    "gate": "layer3-serial-cache-staleness-compose",
    "chain": "Unbound(cache) -> CoreDNS-forwarder(no cache) -> auth",
    "unbound_image": image,
    "cache_ttl_s": int(cache_ttl_f),
    "status": status,
    "pre_change": {"unbound": pre_ub, "coredns_fwd": pre_cd, "D_answer": d(pre_ub, pre_cd)},
    "post_change_immediate": {"unbound": post_ub, "coredns_fwd": post_cd, "D_answer": d(post_ub, post_cd)},
    "reconverged": {"unbound": rec_ub, "coredns_fwd": rec_cd, "D_answer": d(rec_ub, rec_cd)},
    "timestamps_epoch": {
        "pre_unbound_query": t_pre_f,
        "change_promoted": t_promote_f,
        "post_change_unbound_query": float(t_post_ub),
        "reconverged_unbound_query": t_reconv_f,
    },
    "reconverged_after_poll_attempts": int(poll_attempts),
    "propagation_lag_measured_s": lag_measured,
    "propagation_lag_predicted_from_ttl_s": lag_predicted,
    "measurement_note": (
        "propagation_lag_measured_s is a first-observation measurement from ~1s-interval "
        "polling of Unbound starting after promotion. "
        "propagation_lag_predicted_from_ttl_s is the independent mechanistic prediction "
        "(cache entry populated at pre_unbound_query, cache_ttl_s TTL, minus elapsed time "
        "to change_promoted); the two should agree within one poll interval."
    ),
    "finding": finding,
}
raw = json.dumps(report, indent=2, sort_keys=True) + "\n"
Path(out, "decision.json").write_text(raw, encoding="utf-8")
print(raw)
if status != "PASS":
    sys.exit(2)
PY

DECISION_SHA="$(sha256sum "$OUT/decision.json" | awk '{print $1}')"
log "decision SHA-256 $DECISION_SHA"
log "DONE artifact=$OUT"

(
  cd "$OUT"
  find . -type f ! -name 'SHA256SUMS.txt*' ! -name run.log -print0 | sort -z | xargs -0 sha256sum
) > "$OUT/SHA256SUMS.txt.partial"

echo "$OUT"
