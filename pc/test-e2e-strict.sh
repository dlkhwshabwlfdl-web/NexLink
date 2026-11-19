#!/usr/bin/env bash
# NexLink STRICT end-to-end battery — adversarial checks beyond the
# default suite (test-e2e.sh). Drives the real engine against the real
# simphone, a byte-mangling relay, and in-process NXLP phone doubles.
#
#   S1  hostile relay (partial reads/writes) — 1 MiB intact
#   S2  10 MiB down byte-identical; traffic counters honest
#   S2b 1 MiB up (echo) byte-identical
#   S3  8 concurrent flows, mixed sizes, no cross-talk, no stall
#   S4  MTU edges 1399/1400/1401; no packet over the 1400 MTU
#   S5  DNS multi-name + NXDOMAIN passthrough
#   S6  dead DNS upstream fails clean, engine unaffected
#   S7  probe negatives: DNS stage / traffic stage / dead link
#   S8  500 open/close churn cycles
#   S9  destination RST mid-transfer
#   S10 half-close: full response after the app's FIN
#   S11 link severed mid-transfer + recovery
#   S12 silent peer: link declared dead at the 60 s window
#   S13 UDP associations over the link (NXLP double)
#   S14 UDP via simphone's real relay (SKIPs where UDP is blocked)
#   S15 idle UDP associations reaped at the 60 s expiry
#
# Takes a few minutes: S12 and S15 deliberately wait out the engine's
# real 60-second timers (they run concurrently with the other checks).
set -eu
cd "$(dirname "$0")"
export PATH="$HOME/.cargo/bin:$PATH"

echo "== building =="
cargo build --workspace 2>&1 | tail -1

echo "== strict end-to-end =="
./target/debug/e2e_strict
