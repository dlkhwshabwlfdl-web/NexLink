#!/usr/bin/env bash
# NexLink end-to-end test over a REAL TUN device (Linux).
#
# Needs CAP_NET_ADMIN — many sandboxes and CI runners (including the Muse
# VM) drop that capability, so this variant cannot run there. The default
# test-e2e.sh covers the same data path without a TUN device.
#
# Topology under test — the full data path, no mocks in the middle:
#
#   curl / dns_query.py
#        │  kernel routing (203.0.113.0/24 via nx0)
#        ▼
#   TUN device nx0 ─► nxpump ─► nxcore engine (smoltcp stack)
#        │  NXLP flows over a TCP link
#        ▼
#   simphone (phone-side relay semantics: real sockets, DNS interception)
#        │
#        ├─► local HTTP server  (via --map 203.0.113.7:18080)
#        └─► fake DNS resolver  (via --dns, for port-53 flows)
#
# Three checks: (1) HTTP over the tunnel, (2) DNS interception,
# (3) the phone's arm switch refusing a session.
set -u
export PATH="$HOME/.cargo/bin:$PATH"
cd "$(dirname "$0")"
BIN=./target/debug
LOG=/tmp/nexlink-e2e
mkdir -p "$LOG"
PIDS=()

cleanup() {
    for pid in "${PIDS[@]:-}"; do kill "$pid" 2>/dev/null; done
    ip route del 203.0.113.0/24 dev nx0 2>/dev/null
    ip link del nx0 2>/dev/null
}
trap cleanup EXIT

fail() { echo "E2E FAIL: $*" >&2; exit 1; }

echo "== building =="
cargo build -p nxcore -p nxpump -p simphone 2>&1 | tail -1 || fail "build"

echo "== starting local servers =="
python3 -m http.server 18080 --bind 127.0.0.1 --directory test/www >"$LOG/http.log" 2>&1 &
PIDS+=($!)
python3 test/fake_dns.py >"$LOG/dns.log" 2>&1 &
PIDS+=($!)
sleep 1

echo "== starting simphone (armed) =="
"$BIN/simphone" --map 203.0.113.7:18080=127.0.0.1:18080 --dns 127.0.0.1:15353 \
    >"$LOG/simphone.log" 2>&1 &
PIDS+=($!)
sleep 1

echo "== starting nxpump =="
# stdin must stay open: nxpump stops when stdin closes.
sleep 60 | "$BIN/nxpump" --tun nx0 >"$LOG/nxpump.log" 2>&1 &
PIDS+=($!)
for _ in $(seq 1 30); do grep -q "engine running" "$LOG/nxpump.log" 2>/dev/null && break; sleep 0.3; done
grep -q "handshake ok: phone=simphone armed=true" "$LOG/nxpump.log" || { cat "$LOG/nxpump.log"; fail "handshake"; }
ip route add 203.0.113.0/24 dev nx0 || fail "route add"

echo "== test 1: HTTP through the tunnel =="
OUT=$(curl -s --max-time 15 http://203.0.113.7:18080/hello.txt) || fail "curl"
[ "$OUT" = "nexlink-e2e-ok" ] || fail "unexpected HTTP body: $OUT"
echo "   OK: fetched '$OUT' from 203.0.113.7 via the tunnel"

echo "== test 2: DNS interception =="
# 203.0.113.53 is NOT the fake resolver; only phone-side interception of
# port 53 can produce the fake resolver's answer.
python3 test/dns_query.py 203.0.113.53 || fail "dns query"
echo "   OK: port-53 flow was resolved by the phone side"

echo "== test 3: arm switch refuses =="
kill "${PIDS[-1]}" 2>/dev/null; sleep 0.5   # nxpump
kill "${PIDS[-2]}" 2>/dev/null; sleep 0.5   # simphone (armed)
"$BIN/simphone" --armed=false >"$LOG/simphone2.log" 2>&1 &
PIDS+=($!)
sleep 1
"$BIN/nxpump" --tun nx0 </dev/null >"$LOG/nxpump2.log" 2>&1
CODE=$?
[ "$CODE" = "2" ] || { cat "$LOG/nxpump2.log"; fail "expected exit 2 from unarmed nxpump, got $CODE"; }
grep -q "not armed" "$LOG/nxpump2.log" || fail "expected the not-armed message"
echo "   OK: unarmed phone refused the session (exit 2)"

echo "E2E PASS"
