#!/usr/bin/env bash
# StackDiff Package B — P-MALFORMED-RCODE packet timeline capture helper.
# Requires: Docker Compose, dig, tcpdump (sudo), Python harness classifiers.
set -euo pipefail
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

TS=$(date -u +%Y%m%dT%H%M%SZ)
OUT="$ROOT/artifacts/capture-malformed-${TS}"
mkdir -p "$OUT"
echo "OUT=$OUT" | tee "$OUT/env.txt"

COMPOSE=(docker compose -f deploy/compose.yaml -f deploy/compose.adversarial.yaml)

"${COMPOSE[@]}" down --remove-orphans -v || true
docker ps -aq --filter name=deploy | xargs -r docker rm -f || true
sleep 2

export MITM_MODE=malformed-truncated
"${COMPOSE[@]}" up -d --remove-orphans
sleep 8

ok=0
for i in $(seq 1 40); do
  if "${COMPOSE[@]}" logs mitm 2>/dev/null | grep -q "mitm mode=malformed-truncated"; then
    ok=1
    break
  fi
  if "${COMPOSE[@]}" logs mitm 2>/dev/null | grep -q "invalid choice"; then
    "${COMPOSE[@]}" logs mitm | tee "$OUT/mitm-boot-fail.txt"
    exit 2
  fi
  sleep 1
done
"${COMPOSE[@]}" ps | tee "$OUT/compose-ps.txt"
"${COMPOSE[@]}" logs --tail=30 mitm | tee "$OUT/mitm-boot.txt"
test "$ok" = 1

NET_NAME=$(docker inspect "$(${COMPOSE[@]} ps -q auth)" -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}')
BRIDGE=$(docker network inspect "$NET_NAME" -f '{{.Id}}' | cut -c1-12)
BR_IF="br-${BRIDGE}"
echo "NET_NAME=$NET_NAME BR_IF=$BR_IF" | tee -a "$OUT/env.txt"

sudo tcpdump -i any -nn -s 0 -U -w "$OUT/host-published-ports.pcap" \
  '(udp or tcp) and (port 9053 or port 9054)' >/dev/null 2>"$OUT/tcpdump-host.err" &
HOST_PID=$!
sudo tcpdump -i "$BR_IF" -nn -s 0 -U -w "$OUT/dnsnet-bridge.pcap" \
  'udp port 53 or tcp port 53' >/dev/null 2>"$OUT/tcpdump-bridge.err" &
BR_PID=$!
sleep 1

QNAME=agree.lab.stackdiff.

run_dig() {
  local label=$1; shift
  local out="$OUT/dig-${label}.txt"
  set +e
  dig "$@" >"$out" 2>&1
  local rc=$?
  set -e
  echo "rc=$rc" >>"$out"
  echo "=== $label rc=$rc ===" | tee -a "$OUT/dig-summary.txt"
  tail -n 15 "$out" | tee -a "$OUT/dig-summary.txt"
}

run_dig unbound-udp @127.0.0.1 -p 9053 "$QNAME" A +time=2 +tries=1 +noall +answer +additional +comments
run_dig dnsmasq-udp @127.0.0.1 -p 9054 "$QNAME" A +time=2 +tries=1 +noall +answer +additional +comments
run_dig unbound-tcp @127.0.0.1 -p 9053 "$QNAME" A +tcp +time=2 +tries=1 +noall +answer +additional +comments
run_dig dnsmasq-tcp @127.0.0.1 -p 9054 "$QNAME" A +tcp +time=2 +tries=1 +noall +answer +additional +comments

"${COMPOSE[@]}" logs --tail=100 mitm unbound dnsmasq 2>&1 | tee "$OUT/compose-logs.txt"

sleep 1
sudo kill -INT "$HOST_PID" "$BR_PID" 2>/dev/null || true
wait "$HOST_PID" 2>/dev/null || true
wait "$BR_PID" 2>/dev/null || true
sleep 1

{
  echo "# host-published-ports.pcap"
  sudo tcpdump -nn -ttttt -r "$OUT/host-published-ports.pcap" 2>/dev/null || true
  echo
  echo "# dnsnet-bridge.pcap"
  sudo tcpdump -nn -ttttt -r "$OUT/dnsnet-bridge.pcap" 2>/dev/null || true
} | tee "$OUT/tcpdump-decode.txt"

{
  echo "# bridge UDP DNS messages"
  sudo tcpdump -nn -r "$OUT/dnsnet-bridge.pcap" 'udp port 53' 2>/dev/null || true
} | tee "$OUT/tcpdump-udp53.txt"

set +e
python3 classifier/run_adversarial.py --profile P-MALFORMED-RCODE | tee "$OUT/run_adversarial.out"
ADV_RC=$?
set -e
echo "run_adversarial_rc=$ADV_RC" | tee -a "$OUT/env.txt"

docker compose -f deploy/compose.yaml down --remove-orphans || true
docker compose -f deploy/compose.yaml up -d
sleep 5
set +e
python3 classifier/run_smoke.py --compose-file deploy/compose.yaml | tee "$OUT/smoke-after.out"
set -e

(
  cd "$OUT"
  sha256sum ./* 2>/dev/null | tee SHA256SUMS
)

echo "CAPTURE_DONE $OUT"
