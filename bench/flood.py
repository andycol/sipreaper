#!/usr/bin/env python3
"""flood.py — F1: well-formed SIP INVITE flood from a BOUNDED spoofed-source pool.

The source pool lives entirely in 198.18.0.0/15 (the RFC 2544 benchmarking
range — never real address space), so:
  * sipreaper actually bans these sources (bounded => the ban map fills),
  * the XDP map has real entries to drop against (measuring the enforcer, not
    raw UDP-receive cost), and
  * we never touch a real network.

Keep 198.18.0.0/15 OUT of the sipreaper whitelist for the flood — except, for
the Phase 3 security test, deliberately whitelist ONE IP in this range and
assert it never lands in the BPF map (`bpftool map dump`).

Requires scapy and root (raw sockets). Example:
    sudo ./flood.py --dst 10.0.0.10 --dport 5060 --pps 8000 --pool 5000 --secs 60
"""
import argparse
import random
import time

from scapy.all import IP, UDP, Raw, send  # type: ignore

POOL_BASE = (198, 18, 0, 0)  # 198.18.0.0/15


def rand_source(pool_size: int) -> str:
    # Deterministic-ish bounded pool across the /15 (131072 hosts).
    n = random.randrange(pool_size)
    b = POOL_BASE[2] + (n >> 8)
    c = n & 0xFF
    return f"198.{18 + (b >> 8)}.{b & 0xFF}.{c}"


def invite(dst: str, dport: int, src: str) -> IP:
    branch = "z9hG4bK%08x" % random.getrandbits(32)
    callid = "%016x" % random.getrandbits(64)
    body = (
        f"INVITE sip:victim@{dst} SIP/2.0\r\n"
        f"Via: SIP/2.0/UDP {src}:5060;branch={branch}\r\n"
        f"From: <sip:attacker@{src}>;tag={random.getrandbits(32)}\r\n"
        f"To: <sip:victim@{dst}>\r\n"
        f"Call-ID: {callid}\r\n"
        f"CSeq: 1 INVITE\r\n"
        f"Contact: <sip:attacker@{src}:5060>\r\n"
        f"Max-Forwards: 70\r\n"
        f"Content-Type: application/sdp\r\n"
        f"Content-Length: 0\r\n\r\n"
    )
    return IP(src=src, dst=dst) / UDP(sport=5060, dport=dport) / Raw(load=body)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--dst", required=True)
    ap.add_argument("--dport", type=int, default=5060)
    ap.add_argument("--pps", type=int, default=8000, help="packets per second")
    ap.add_argument("--pool", type=int, default=5000, help="distinct source IPs")
    ap.add_argument("--secs", type=int, default=60)
    args = ap.parse_args()

    interval = 1.0 / args.pps
    end = time.monotonic() + args.secs
    sent = 0
    while time.monotonic() < end:
        pkt = invite(args.dst, args.dport, rand_source(args.pool))
        send(pkt, verbose=0)
        sent += 1
        time.sleep(interval)
    print(f"sent {sent} INVITEs from a {args.pool}-IP pool in 198.18.0.0/15")


if __name__ == "__main__":
    main()
