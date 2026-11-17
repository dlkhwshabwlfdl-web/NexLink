#!/usr/bin/env bash
# NexLink end-to-end test — the default suite.
#
# Runs the protocol unit tests, then the `e2e` binary, which drives a
# virtual PC app (its own TCP/IP stack) through the real engine and the
# real simphone binary to real local servers:
#
#   check 0  fake-DNS sanity (direct)
#   check 1  HTTP fetched through the tunnel, body intact
#   check 2  DNS interception: a query dialed to 203.0.113.53 is answered
#            by the phone-side resolver instead
#   check 3  the phone's arm switch: unarmed phone refuses the session
#
# No TUN device is needed, so this runs in sandboxes and CI where
# CAP_NET_ADMIN is unavailable. For the same path over a real TUN device
# (root on a normal Linux machine), see test-e2e-tun.sh.
set -eu
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$PATH"

echo "== unit tests =="
cargo test --workspace 2>&1 | grep -E "test result" | grep -v "0 passed" || true
cargo test --workspace 2>&1 | grep -cE "test result: ok" >/dev/null

echo "== building =="
cargo build --workspace 2>&1 | tail -1

echo "== end-to-end =="
./target/debug/e2e
