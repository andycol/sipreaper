# sipreaper XDP benchmark (Phase 5)

This harness proves two things before the XDP enforcer is allowed to stand
alone (`enforcer.xdp.standalone=true`):

1. **No overhead** — attaching XDP + per-packet map lookups + the default-on
   stats counter does not tax the legitimate SIP path.
2. **Headroom** — under a source-IP flood, XDP yields strictly higher legit
   throughput and lower `%soft` (NET_RX softirq) than the iptables/ipset
   baseline, ideally absorbing the flood entirely.

Phase 5 is the **gating milestone**: until all three numeric criteria below
pass on the real SUT, the shipped default stays `standalone=false` (composite
with iptables as the safety net).

## Topology

Three hosts on an isolated L2 segment:

- **SUT** — OpenSIPS + sipreaper + XDP.
- **LOAD** — legitimate sipp (`register.xml`, `register_tls.xml`).
- **ATTACK** — flood generators (`flood.py`).

LOAD and ATTACK are on separate NICs/hosts so the flood can't starve the legit
generator.

## Confounder controls (applied IDENTICALLY to every cell)

`run-matrix.sh` pins these; do not vary them between cells:

- **IRQ affinity** of the SIP NIC queues fixed; record `ethtool -l`/`-x`.
- **GRO/LRO/RSS** fixed to the same value every cell (`ethtool -K eth0 gro on
  lro off`). Note: **generic** XDP runs *after* GRO, **native** runs before —
  so generic-mode A/B numbers are **not** comparable to native-mode numbers.
  State the mode in the report.
- **Neighbour/route cache** sized for the spoofed-source volume; confirm
  198.18.0.0/15 is routed off-link (no ARP-per-source storm).
- **≥5 runs per cell**, first/last 10s discarded, report mean ± stddev. (3 runs
  is too few — 2% deltas hide inside run-to-run SIP variance, which is why the
  overhead threshold is 5%, not 2%.)

OpenSIPS must not be the bottleneck: workers ≥ cores, trivial REGISTER/INVITE
script, no DB on the hot path, `load` < ~75% in cell A. **Verify the MI stat
names for your OpenSIPS major version (2.x vs 3.x differ).**

## The matrix

| Cell | XDP | Attack | Primary read |
|------|-----|--------|--------------|
| A | off | none | baseline reg/s & calls/s, `%soft`, OpenSIPS `%CPU`/`load` |
| B | on | none | **overhead** vs A (incl. default-on stats counter) |
| C | off | F1/F2 (bounded) | legit collapse + `%soft` spike |
| D | on | F1/F2 (bounded) | **headroom** vs C |

Optional E/F: existing `ipset` drop and the `hashlimit` prefilter under flood,
comparing XDP against shipping code.

Toggle XDP between cells via `enforcer.xdp.enabled` + restart, or the no-restart
kill switch `POST /api/v1/xdp/detach`.

## Flood generators (BOTH must be bannable / bounded-source)

- **F1** — `flood.py`: well-formed INVITEs, spoofed sources from a bounded pool
  in 198.18.0.0/15 (~5–10k distinct IPs). Triggers real bans + fills the map.
- **F2** — line-rate saturation, **also bounded** (reuse the 198.18/15 pool, or
  `preseed.sh` the map first). **`hping3 --rand-source` is rejected**: it floods
  the entire IPv4 space, sipreaper never bans those, the map stays empty, and
  F2 would measure raw UDP-receive cost instead of the enforcer.
- `preseed.sh` fills the map/ipset to 1k/10k/50k to measure steady-state lookup
  cost (O(1) hash vs growing iptables chain) and to give F2 entries to drop.

## TLS/TCP (5061) case

Run a SIP-over-TCP/TLS REGISTER (`register_tls.xml`, `sipp -t l1`) so the TCP
drop path is exercised and the mid-stream teardown of in-flight calls from a
banned source is documented. The 5% overhead threshold applies separately here.

## Measurement (per run; discard first/last 10s)

- sipp `-trace_stat` CSV: `SuccessfulCall`, `CallRate`, `FailedCall`,
  `FailedMaxUDPRetrans`, `FailedTimeoutOnRecv`, `ResponseTime`.
- `mpstat -P ALL 1` (`%soft`) + `mpstat -I SCPU` (NET_RX breakdown).
- `pidstat` for OpenSIPS workers and the sipreaper PID.
- `tcpdump` count of INVITEs reaching userspace. **Note:** XDP runs *before* the
  AF_PACKET tap, so captured flood volume falling to ~0 with XDP on is BOTH the
  success signal AND the detection-blindness behavior — record both readings.
- `bpftool map dump pinned /sys/fs/bpf/sipreaper/stats` → `pkts_dropped` per
  window (cross-check against the tcpdump ~0).
- OpenSIPS MI deltas: `rcv_requests`, `drop_requests`, `err_requests`, `load:`.

## Numeric pass criteria

1. **No overhead (B vs A):** legit reg/s and calls/s within `|B−A|/A < 5%`,
   `FailedCall` unchanged, OpenSIPS worker `%CPU` within ~1 point — with the
   stats counter ON. Same threshold for the TLS/TCP 5061 case.
2. **Headroom (D vs C):** legit throughput strictly higher in D; target D ≈ A
   (flood fully absorbed); corroborated by lower `%soft`, ~0 captured flood
   INVITEs, `stats.pkts_dropped` ≈ flood volume, OpenSIPS `rcv_requests`/`load`
   in D ≈ A while C climbs.
3. **Map-fill independence:** D repeated at 1k/10k/50k preseeded bans shows no
   legit-throughput degradation with map size.

A signed-off report meeting all three is attached to the PR. Failure blocks
`standalone=true`; the composite-with-iptables default stays shipped.

## Security cross-check (Phase 3 gap)

Whitelist ONE IP inside the 198.18/15 flood range, run F1, and assert via
`bpftool map dump pinned /sys/fs/bpf/sipreaper/banned_v4` that the whitelisted
IP never appears in the map. Keep the rest of 198.18/15 OUT of the whitelist.

## Files

- `register.xml`, `register_tls.xml`, `users.csv` — sipp legit scenarios.
- `flood.py` — F1 bounded-source INVITE flood (scapy).
- `preseed.sh` — fill XDP map / ipset to a target size.
- `run-matrix.sh` — drive a cell, pin confounders, collect metrics.
- `phase0-hostcheck.sh` — Phase 0 feasibility spike (run first).
