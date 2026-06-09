#!/usr/bin/env bash
# run-matrix.sh — drive the Phase 5 A/B/C/D benchmark cells and collect metrics.
#
#   A: XDP off, no attack      -> baseline reg/s & calls/s, %soft
#   B: XDP on,  no attack      -> OVERHEAD test vs A (includes default-on stats counter)
#   C: XDP off, bounded flood  -> legit collapse + %soft spike (ipset/iptables)
#   D: XDP on,  bounded flood  -> HEADROOM test vs C (target D ~ A)
#
# This script enforces the confounder controls that make A/B/C/D comparable:
# pinned IRQ affinity, fixed GRO/LRO/RSS, sized neighbor cache. Toggling XDP
# on/off between cells is done by you (config enforcer.xdp.enabled + restart, or
# POST /api/v1/xdp/detach) — this script only sets up, loads, and measures.
#
# Run from the SUT. Edit the CONFIG block. Needs: sipp, mpstat (sysstat),
# pidstat, tcpdump, bpftool, ethtool. ≥5 runs per cell; first/last 10s discarded.
set -euo pipefail

# --- CONFIG -----------------------------------------------------------------
SUT_IP=${SUT_IP:-10.0.0.10}
IFACE=${IFACE:-eth0}
LOAD_IP=${LOAD_IP:-10.0.0.20}
SIP_PORT=${SIP_PORT:-5060}
OPENSIPS_PIDS=${OPENSIPS_PIDS:-$(pgrep -d, opensips || true)}
REAPER_PID=${REAPER_PID:-$(pgrep -x sipreaper || true)}
RUNS=${RUNS:-5}
WINDOW=${WINDOW:-90}      # seconds of measurement per run
OUTDIR=${OUTDIR:-./bench-out}
CELL=${1:?usage: $0 <A|B|C|D> [pre_seed_count]}
PRESEED=${2:-0}
# ---------------------------------------------------------------------------

mkdir -p "$OUTDIR"

pin_confounders() {
  echo ">> pinning confounders (IRQ affinity, GRO/LRO, neigh cache)"
  ethtool -K "$IFACE" gro on lro off 2>/dev/null || true   # SAME value every cell
  ethtool -l "$IFACE" 2>/dev/null | sed -n '1,12p' | tee "$OUTDIR/$CELL.ethtool-l.txt"
  ethtool -x "$IFACE" 2>/dev/null | head -20 | tee "$OUTDIR/$CELL.ethtool-x.txt" || true
  # Size neighbour/route cache so the spoofed-source volume doesn't perturb CPU.
  sysctl -w net.ipv4.neigh.default.gc_thresh1=8192 \
            net.ipv4.neigh.default.gc_thresh2=16384 \
            net.ipv4.neigh.default.gc_thresh3=32768 >/dev/null
  echo "   (ensure 198.18.0.0/15 is routed off-link via the test gateway — no ARP storm)"
}

measure_bg() {
  local tag=$1
  mpstat -P ALL 1 "$WINDOW" >"$OUTDIR/$tag.mpstat.txt" &
  mpstat -I SCPU -P ALL 1 "$WINDOW" >"$OUTDIR/$tag.mpstat-irq.txt" &
  [[ -n "$OPENSIPS_PIDS" ]] && pidstat -p "$OPENSIPS_PIDS" 1 "$WINDOW" >"$OUTDIR/$tag.pidstat-opensips.txt" &
  [[ -n "$REAPER_PID" ]] && pidstat -p "$REAPER_PID" 1 "$WINDOW" >"$OUTDIR/$tag.pidstat-reaper.txt" &
  timeout "$WINDOW" tcpdump -ni "$IFACE" -w "$OUTDIR/$tag.flood.pcap" "udp port $SIP_PORT" 2>/dev/null &
}

snapshot_stats() {  # XDP drop counter + OpenSIPS MI (version-correct names!)
  local tag=$1 when=$2
  if [[ -e /sys/fs/bpf/sipreaper/stats ]]; then
    bpftool map dump pinned /sys/fs/bpf/sipreaper/stats >"$OUTDIR/$tag.stats.$when.txt" 2>/dev/null || true
  fi
  # opensips-cli -x mi get_statistics rcv_requests drop_requests err_requests load:
  command -v opensips-cli >/dev/null && \
    opensips-cli -x mi get_statistics all >"$OUTDIR/$tag.mi.$when.txt" 2>/dev/null || true
}

run_legit() {  # constant legit load, held identical across all cells
  local tag=$1
  sipp "$SUT_IP:$SIP_PORT" -sf register.xml -inf users.csv \
    -r 200 -rp 1000 -l 2000 -m $((200 * WINDOW)) \
    -trace_stat -fd 1 -stf "$OUTDIR/$tag.sipp.csv" -trace_err \
    -i "$LOAD_IP" -p "$SIP_PORT" -nd -timeout 5s -bg
}

echo "=== CELL $CELL (preseed=$PRESEED) ==="
pin_confounders
[[ "$PRESEED" -gt 0 ]] && { echo ">> pre-seeding $PRESEED bans"; sudo ./preseed.sh xdp "$PRESEED" || sudo ./preseed.sh ipset "$PRESEED"; }

for r in $(seq 1 "$RUNS"); do
  tag="$CELL.run$r"
  echo ">> run $r/$RUNS ($tag)"
  snapshot_stats "$tag" start
  measure_bg "$tag"
  run_legit "$tag"
  if [[ "$CELL" == "C" || "$CELL" == "D" ]]; then
    echo "   launching F1 bounded flood from the ATTACK host (run flood.py there)"
    echo "   e.g.: sudo ./flood.py --dst $SUT_IP --dport $SIP_PORT --pps 8000 --pool 5000 --secs $WINDOW"
  fi
  sleep "$WINDOW"
  snapshot_stats "$tag" end
  wait || true
  echo "   captured INVITEs reaching userspace: $(tcpdump -r "$OUTDIR/$tag.flood.pcap" 2>/dev/null | grep -c INVITE || echo '?')"
done

echo "=== done; raw data in $OUTDIR/ ==="
echo "Pass criteria (see bench/README.md):"
echo "  1. |B-A|/A < 5% on reg/s & calls/s (with stats counter ON)"
echo "  2. D strictly > C; target D ~ A; lower %soft; ~0 captured flood INVITEs in D"
echo "  3. D unchanged at 1k/10k/50k preseeded bans"
