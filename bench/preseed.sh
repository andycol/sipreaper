#!/usr/bin/env bash
# preseed.sh — fill the XDP ban map (and/or the ipset) to a target size so the
# benchmark measures STEADY-STATE lookup cost independent of the ban ramp, and
# so the F2 saturation flood has entries to drop against.
#
# Sources are drawn from 198.18.0.0/15 (RFC 2544 bench range). This validates
# O(1) hash lookup vs a growing iptables chain.
#
# Usage:
#   sudo ./preseed.sh xdp   10000        # bpftool: seed banned_v4 with 10k IPs
#   sudo ./preseed.sh ipset 10000 sipreaper
set -euo pipefail

BACKEND="${1:?usage: $0 xdp|ipset <count> [setname]}"
COUNT="${2:?count required}"
SETNAME="${3:-sipreaper}"
MAP=/sys/fs/bpf/sipreaper/banned_v4

gen_ip() {  # $1 = index in [0, 131072)
  local n=$1
  printf '198.%d.%d.%d' $((18 + (n >> 16 & 1))) $(((n >> 8) & 0xFF)) $((n & 0xFF))
}

case "$BACKEND" in
  xdp)
    command -v bpftool >/dev/null || { echo "bpftool required" >&2; exit 1; }
    [[ -e "$MAP" ]] || { echo "map $MAP not found — is sipreaper running with xdp enabled?" >&2; exit 1; }
    echo "seeding $COUNT entries into $MAP ..."
    for ((i = 0; i < COUNT; i++)); do
      ip=$(gen_ip "$i")
      IFS=. read -r a b c d <<<"$ip"
      # key = 4 raw bytes (hex), value = 1 byte. Matches the program's __u8[4] key.
      bpftool map update pinned "$MAP" \
        key hex "$(printf '%02x %02x %02x %02x' "$a" "$b" "$c" "$d")" \
        value hex 01 any
    done
    echo "done; entries: $(bpftool map dump pinned "$MAP" | grep -c 'key:')"
    ;;
  ipset)
    command -v ipset >/dev/null || { echo "ipset required" >&2; exit 1; }
    ipset create "$SETNAME" hash:net family inet -exist
    echo "seeding $COUNT entries into ipset $SETNAME ..."
    for ((i = 0; i < COUNT; i++)); do ipset add "$SETNAME" "$(gen_ip "$i")" -exist; done
    echo "done; ipset size: $(ipset list "$SETNAME" | grep -c '^198\.')"
    ;;
  *)
    echo "unknown backend $BACKEND (want xdp|ipset)" >&2; exit 2 ;;
esac
