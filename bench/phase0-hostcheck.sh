#!/usr/bin/env bash
# phase0-hostcheck.sh — sipreaper XDP feasibility spike (Phase 0).
#
# Run this ON THE TARGET HOST (the SUT). It is READ-ONLY by default: it probes
# kernel version, BTF, bpffs, the SIP-facing NIC + driver, GRO/LRO/RSS state,
# and the eBPF toolchain, then OPTIONALLY attaches a throwaway count-only XDP
# program to confirm native vs generic mode and the "already-attached" errno.
#
# Usage:
#   ./phase0-hostcheck.sh <iface>            # checks only (no attach)
#   ./phase0-hostcheck.sh <iface> --attach   # also do the throwaway attach test
#
# Nothing here mutates persistent host state; the attach test detaches itself.
set -uo pipefail

IFACE="${1:-}"
ATTACH="${2:-}"
if [[ -z "$IFACE" ]]; then
  echo "usage: $0 <iface> [--attach]" >&2
  exit 2
fi

hr() { printf '\n=== %s ===\n' "$1"; }
have() { command -v "$1" >/dev/null 2>&1; }

hr "Kernel"
uname -r
KREL=$(uname -r)
KMAJ=${KREL%%.*}; KREST=${KREL#*.}; KMIN=${KREST%%.*}
if (( KMAJ > 5 || (KMAJ == 5 && KMIN >= 8) )); then
  echo "OK: kernel supports CAP_BPF + bpf_link XDP (>= 5.8)"
elif (( KMAJ == 5 && KMIN >= 7 )); then
  echo "OK: kernel supports bpf_link XDP (>= 5.7); CAP_BPF needs 5.8 (use CAP_SYS_ADMIN/CAP_SYS_RESOURCE)"
else
  echo "WARN: kernel < 5.7 — bpf_link XDP unsupported; sipreaper will stay on iptables"
fi

hr "BTF"
if [[ -r /sys/kernel/btf/vmlinux ]]; then
  echo "OK: /sys/kernel/btf/vmlinux present"
else
  echo "WARN: kernel BTF absent — CO-RE/load may fail; sipreaper degrades to iptables"
fi

hr "bpffs (/sys/fs/bpf)"
if mount | grep -q 'on /sys/fs/bpf '; then
  echo "OK: bpffs mounted"
else
  echo "WARN: bpffs NOT mounted. Mount with: sudo mount -t bpf bpf /sys/fs/bpf"
  echo "      (systemd unit uses RequiresMountsFor=/sys/fs/bpf)"
fi

hr "Interface + driver: $IFACE"
if ! ip -d link show "$IFACE" >/dev/null 2>&1; then
  echo "ERROR: interface $IFACE not found"; exit 1
fi
ip -d link show "$IFACE" | sed -n '1,3p'
if have ethtool; then
  echo "--- driver ---"; ethtool -i "$IFACE" 2>/dev/null | sed -n '1,4p'
  echo "--- GRO/LRO (pin identically across all benchmark cells) ---"
  ethtool -k "$IFACE" 2>/dev/null | grep -E 'generic-receive-offload|large-receive-offload'
  echo "--- RSS / queue count ---"
  ethtool -l "$IFACE" 2>/dev/null | sed -n '1,12p'
else
  echo "WARN: ethtool not installed — install to record driver/GRO/RSS"
fi
echo "--- MTU / multi-buffer hint ---"
ip link show "$IFACE" | grep -o 'mtu [0-9]*'

hr "eBPF toolchain (generate-time only)"
for t in clang llvm-strip bpftool; do
  if have "$t"; then printf 'OK: %s -> %s\n' "$t" "$($t --version 2>/dev/null | head -1)"; else echo "MISSING: $t (needed only for 'make generate')"; fi
done

if [[ "$ATTACH" == "--attach" ]]; then
  hr "Throwaway attach test (native -> generic fallback)"
  if [[ $EUID -ne 0 ]]; then echo "ERROR: --attach needs root"; exit 1; fi
  if ! have ip; then echo "ERROR: iproute2 'ip' required"; exit 1; fi
  # Use a tiny prebuilt return-XDP_PASS object if available; otherwise instruct.
  echo "Attempting native (driver) attach..."
  if ip link set dev "$IFACE" xdpdrv obj /dev/null sec xdp 2>/tmp/xdp.err; then
    echo "OK: native attach accepted (object load may still need a real prog)"
    ip link set dev "$IFACE" xdpdrv off 2>/dev/null
  else
    echo "native attach errno: $(cat /tmp/xdp.err)"
    echo "Falling back to generic (xdpgeneric)..."
    if ip link set dev "$IFACE" xdpgeneric obj /dev/null sec xdp 2>/tmp/xdp.err; then
      echo "OK: generic attach path available"
      ip link set dev "$IFACE" xdpgeneric off 2>/dev/null
    else
      echo "generic attach errno: $(cat /tmp/xdp.err)"
    fi
  fi
  echo
  echo "NOTE: /dev/null is not a valid program — the goal here is only to read"
  echo "the errno (EOPNOTSUPP => native unsupported; EBUSY/EEXIST => a prog is"
  echo "already attached). For a real load test, build sipreaper and run:"
  echo "  sudo -E go test ./internal/banner/ -run TestClassification -v"
fi

hr "Summary"
echo "Record in the PR: driver name+version, native-vs-generic verdict, kernel"
echo "version, bpffs status, GRO/RSS/queue state, the already-attached errno,"
echo "and clang/bpftool versions. Generic-only NICs shrink the %soft win — set"
echo "benchmark expectations accordingly (Phase 5)."
