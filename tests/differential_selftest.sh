#!/usr/bin/env bash
#
# Differential-harness end-to-end self-test (no console required).
#
# Proves the two invariants the fidelity loop rests on, using the REAL binaries over loopback:
#   1. Sanity floor  -- the emulator compared against itself yields ZERO deviations. If this ever
#                       fails, the driver is nondeterministic or the comparator is over-reporting.
#   2. Divergence    -- a known value difference (clean vs raised-channel scenario) surfaces as
#                       named, path-resolved deviations. If this fails, the comparator is
#                       under-reporting (false negatives) or the battery isn't observing the node.
#
# The comparator's decode/correlation LOGIC is unit-tested in tools/compare.rs (`cargo test
# --example wingcapture`); this script covers the parts those can't: real driver + proxy + capture.
#
# Run from anywhere: `libwing/tests/differential_selftest.sh`
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/../.." && pwd)"
SCEN="$ROOT/crates/wing-emulator/tests/fixtures/scenarios"

echo "building binaries..."
cargo build -q -p wing-emulator --bin wing-emulator
( cd "$ROOT/libwing" && cargo build -q --example wingcapture --example wingdrive )

EMU="$ROOT/target/debug/wing-emulator"
WC="$ROOT/libwing/target/debug/examples/wingcapture"
WD="$ROOT/libwing/target/debug/examples/wingdrive"

WORK="$(mktemp -d)"
declare -a PIDS=()
cleanup() { for p in "${PIDS[@]:-}"; do kill -9 "$p" 2>/dev/null || true; done; wait 2>/dev/null || true; rm -rf "$WORK"; }
trap cleanup EXIT

Q="$WORK/quar"
"$WC" --init-quarantine "$Q" >/dev/null

# capture <scenario-json> <output-name> <emulator-port>
capture() {
  "$EMU" --control "127.0.0.1:$3" --scenario "$1" --shutdown-after-ms 60000 >"$WORK/emu_$2.log" 2>&1 &
  local ep=$!; PIDS+=("$ep"); disown "$ep" 2>/dev/null || true; sleep 1
  "$WC" --proxy-native 127.0.0.1:0 "127.0.0.1:$3" "$Q" "$2" --allow-state-changing --seconds 30 \
    >"$WORK/px_$2.log" 2>&1 &
  local pp=$!
  local addr=""
  for _ in $(seq 1 50); do
    addr="$(grep -oE '127\.0\.0\.1:[0-9]+' "$WORK/px_$2.log" | head -1 || true)"
    [ -n "$addr" ] && break; sleep 0.1
  done
  [ -n "$addr" ] || { echo "FAIL: proxy never came up for $2"; cat "$WORK/px_$2.log"; exit 1; }
  "$WD" --target "$addr" --gets 48 --timeout-ms 150 --meter-secs 2 >"$WORK/wd_$2.log" 2>&1
  wait "$pp"
}

# 1) Sanity floor
capture "$SCEN/clean.json" floor-a.wingcap 34640
capture "$SCEN/clean.json" floor-b.wingcap 34641
"$WC" --compare-fidelity "$Q/floor-a.wingcap" "$Q/floor-b.wingcap" "$WORK/floor.txt" >/dev/null
grep -q '^# deviations: 0$' "$WORK/floor.txt" \
  || { echo "FAIL: sanity floor is not 0 deviations:"; cat "$WORK/floor.txt"; exit 1; }
echo "PASS: sanity floor = 0 deviations"

# 2) Known divergence
capture "$SCEN/clean.json" clean.wingcap 34642
capture "$SCEN/raised-channel.json" raised.wingcap 34643
"$WC" --compare-fidelity "$Q/clean.wingcap" "$Q/raised.wingcap" "$WORK/neg.txt" >/dev/null
grep -q 'path=/ch/1/fdr' "$WORK/neg.txt" \
  || { echo "FAIL: /ch/1/fdr divergence not caught:"; cat "$WORK/neg.txt"; exit 1; }
grep -q 'path=/ch/1/name' "$WORK/neg.txt" \
  || { echo "FAIL: /ch/1/name divergence not caught:"; cat "$WORK/neg.txt"; exit 1; }
echo "PASS: value divergences surfaced as named deviations"

echo "differential self-test OK"
